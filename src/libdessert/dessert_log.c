/******************************************************************************
 Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).
 All rights reserved.

 These sources were originally developed by Philipp Schmidt
 at Freie Universitaet Berlin (http://www.fu-berlin.de/),
 Computer Systems and Telematics / Distributed, Embedded Systems (DES) group
 (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)
 ------------------------------------------------------------------------------
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program. If not, see http://www.gnu.org/licenses/ .
 ------------------------------------------------------------------------------
 For further information and questions please use the web site
 http://www.des-testbed.net/
 *******************************************************************************/

#include "dessert_internal.h"
#include "dessert.h"
#include <sys/stat.h>
#include <signal.h>

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

/* data storage */
/** logfile file pointer to use with DESSERT_OPT_LOGFILE */
static FILE* _dessert_logfd = NULL;
#ifdef HAVE_LIBZ
static gzFile* _dessert_logfdgz = NULL;
#endif

#define _DESSERT_LOGFLAG_SYSLOG   0x01
#define _DESSERT_LOGFLAG_LOGFILE  0x02
#define _DESSERT_LOGFLAG_STDERR   0x04
#define _DESSERT_LOGFLAG_RBUF     0x08
#define _DESSERT_LOGFLAG_GZ       0x10

#ifndef LOG_STYLE_OLD
#   define LOG_STYLE_OLD 0
#endif

static int _dessert_logflags = _DESSERT_LOGFLAG_STDERR;
static int _dessert_loglevel = LOG_INFO;
static dessert_periodic_t* _dessert_log_flush_periodic = NULL;

/* the logging ringbuffer */
static char* _dessert_logrbuf = NULL; /* pointer to begin */
static int _dessert_logrbuf_len = 0; /* length in lines (DESSERT_LOGLINE_MAX*_dessert_logrbuf_len*sizeof(char) would be in bytes) */
static int _dessert_logrbuf_cur = 0; /* current position */
static int _dessert_logrbuf_used = 0; /* used slots */
static pthread_rwlock_t _dessert_logrbuf_len_lock = PTHREAD_RWLOCK_INITIALIZER; /* for resizing */
static pthread_mutex_t _dessert_logrbuf_mutex = PTHREAD_MUTEX_INITIALIZER; /* for moving _dessert_logrbuf_cur */
static pthread_mutex_t _dessert_logfile_mutex = PTHREAD_MUTEX_INITIALIZER; /* to prevent simultaneous accesses from threads */

/* internal functions forward declarations \todo cleanup */

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * L O G   F A C I L I T Y
 *
 ******************************************************************************/

/** Configure dessert logging framework and sets up logging.
 *
 * @param opts OR'd flags - @see DESSERT_LOG_*
 * @return DESSERT_OK
 *
 * %DESCRIPTION:
 **/
dessert_result dessert_logcfg(uint16_t opts) {
    char dessert_logprefix[32];
    snprintf(dessert_logprefix, sizeof(dessert_logprefix), "dessert/%s", dessert_proto);

    pthread_rwlock_wrlock(&dessert_cfglock);

    /* configure logging */
    if((opts & DESSERT_LOG_SYSLOG) && !(opts & DESSERT_LOG_NOSYSLOG)) {
        if(!(_dessert_logflags & _DESSERT_LOGFLAG_SYSLOG)) {
            /* initialize syslog channel */
            openlog(dessert_logprefix, LOG_PID, LOG_DAEMON);
        }

        _dessert_logflags |= _DESSERT_LOGFLAG_SYSLOG;
    }
    else if(!(opts & DESSERT_LOG_SYSLOG) && (opts & DESSERT_LOG_NOSYSLOG)) {
        if(_dessert_logflags & _DESSERT_LOGFLAG_SYSLOG) {
            /* close syslog channel */
            closelog();
        }

        _dessert_logflags &= ~_DESSERT_LOGFLAG_SYSLOG;
    }

    if((opts & DESSERT_LOG_STDERR) && !(opts & DESSERT_LOG_NOSTDERR)
       && !(_dessert_status & _DESSERT_STATUS_DAEMON)) {
        _dessert_logflags |= _DESSERT_LOGFLAG_STDERR;
    }
    else if((!(opts & DESSERT_LOG_STDERR) && (opts & DESSERT_LOG_NOSTDERR))
            || (_dessert_status & _DESSERT_STATUS_DAEMON)) {
        _dessert_logflags &= ~_DESSERT_LOGFLAG_STDERR;
    }

#ifdef HAVE_LIBZ

    // enable or disable compression
    if((opts & DESSERT_LOG_GZ) && !(opts & DESSERT_LOG_NOGZ)) {
        _dessert_logflags |= _DESSERT_LOGFLAG_GZ;
    }
    else if((!(opts & DESSERT_LOG_GZ) && (opts & DESSERT_LOG_NOGZ))) {
        _dessert_logflags &= ~_DESSERT_LOGFLAG_GZ;
    }

#endif

    if((opts & DESSERT_LOG_FILE) && !(opts & DESSERT_LOG_NOFILE)
       && (_dessert_logfd != NULL
#ifdef HAVE_LIBZ
           || _dessert_logfdgz != NULL
#endif
          )) {
        _dessert_logflags |= _DESSERT_LOGFLAG_LOGFILE;
    }
    else if((!(opts & DESSERT_LOG_FILE) && (opts & DESSERT_LOG_NOFILE))
            || (_dessert_logfd == NULL
#ifdef HAVE_LIBZ
                && _dessert_logfdgz == NULL
#endif
               )) {
        _dessert_logflags &= ~_DESSERT_LOGFLAG_LOGFILE;
    }

    if((opts & DESSERT_LOG_RBUF) && !(opts & DESSERT_LOG_NORBUF)) {
        _dessert_logflags |= _DESSERT_LOGFLAG_RBUF;
    }
    else if(!(opts & DESSERT_LOG_RBUF) && (opts & DESSERT_LOG_NORBUF)) {
        _dessert_logflags &= ~_DESSERT_LOGFLAG_RBUF;
    }

    pthread_rwlock_unlock(&dessert_cfglock);

    return DESSERT_OK;
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * L O G   F A C I L I T Y
 *
 ******************************************************************************/

static char* _dessert_log_rbuf_nextline(void) {
    char* r = NULL;
    pthread_mutex_lock(&_dessert_logrbuf_mutex);

    if(_dessert_logrbuf_len > 0) {
        if(_dessert_logrbuf_cur >= _dessert_logrbuf_len) {
            _dessert_logrbuf_cur = 0;
        }

        r = _dessert_logrbuf + (DESSERT_LOGLINE_MAX * _dessert_logrbuf_cur);
        _dessert_logrbuf_cur++;

        if(_dessert_logrbuf_used < _dessert_logrbuf_len - 1) {
            _dessert_logrbuf_used++;
        }
    }

    pthread_mutex_unlock(&_dessert_logrbuf_mutex);

    return (r);
}

/** internal log function
 *
 * @internal
 *
 * @param[in] level loglevel from <syslog.h>
 * @param[in] *func function name called from
 * @param[in] *file file name called from
 * @param[in] *line line called from
 * @param[in] *fmt printf format string
 * @param[in] ... (var-arg) printf like variables
 **/
void _dessert_log(int level, const char* func, const char* file, int line, const char* fmt, ...) {
    if(_dessert_logflags == 0 || _dessert_loglevel < level) {
        return;
    }

    char pos[80];
    snprintf(pos, sizeof(pos), "(%s@%s:%d)", func, file, line);

    va_list args;
    va_start(args, fmt);

    char msg[DESSERT_LOGLINE_MAX];
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if((_dessert_logflags & _DESSERT_LOGFLAG_SYSLOG) && (level <= LOG_DEBUG)) {
        syslog(level, "%s %s", msg, pos);
    }

    if(_dessert_logflags & (_DESSERT_LOGFLAG_LOGFILE | _DESSERT_LOGFLAG_STDERR | _DESSERT_LOGFLAG_RBUF)) {
        char timestamp[64];
        struct timeval current_time;
        struct tm current_time_members;
        gettimeofday(&current_time, NULL);
        localtime_r(&current_time.tv_sec, &current_time_members);
        snprintf(timestamp,
                 sizeof(timestamp),
                 "%04d-%02d-%02d %02d:%02d:%02d.%03d%+05.1f",
                 current_time_members.tm_year + 1900,
                 current_time_members.tm_mon + 1,
                 current_time_members.tm_mday,
                 current_time_members.tm_hour,
                 current_time_members.tm_min,
                 current_time_members.tm_sec,
                 (int) current_time.tv_usec / 1000,
                 (double) current_time_members.tm_gmtoff / (60 * 60));

        const char* log_type;

        switch(level) {
            case LOG_EMERG:
                log_type = "EMERG: ";
                break;
            case LOG_ALERT:
                log_type = "ALERT: ";
                break;
            case LOG_CRIT:
                log_type = "CRIT:  ";
                break;
            case LOG_ERR:
                log_type = "ERR:   ";
                break;
            case LOG_WARNING:
                log_type = "WARN:  ";
                break;
            case LOG_NOTICE:
                log_type = "NOTICE:";
                break;
            case LOG_INFO:
                log_type = "INFO:  ";
                break;
            case LOG_DEBUG:
                log_type = "DEBUG: ";
                break;
            case LOG_TRACE:
                log_type = "TRACE: ";
                break;
            default:
                log_type = "XXX:   ";
                break;
        }

        if(_dessert_logflags & _DESSERT_LOGFLAG_LOGFILE) {
            pthread_mutex_lock(&_dessert_logfile_mutex);

            if(_dessert_logfd != NULL) {
#if LOG_STYLE_OLD
                fprintf(_dessert_logfd, "%s %s %s\n%80s\n", timestamp, log_type, msg, pos);
#else
                fprintf(_dessert_logfd, "%s %s %s %s\n", timestamp, log_type, msg, pos);
#endif
            }

#ifdef HAVE_LIBZ
            else if(_dessert_logfdgz != NULL) {
#if LOG_STYLE_OLD
                gzprintf(_dessert_logfdgz, "%s %s %s\n%80s\n", timestamp, log_type, msg, pos);
#else
                gzprintf(_dessert_logfdgz, "%s %s %s %s\n", timestamp, log_type, msg, pos);
#endif
            }

#endif
            pthread_mutex_unlock(&_dessert_logfile_mutex);
        }

        if(_dessert_logflags & _DESSERT_LOGFLAG_STDERR) {
#if LOG_STYLE_OLD
            fprintf(stderr, "%s %s %s\n%80s\n", timestamp, log_type, msg, pos);
#else
            fprintf(stderr, "%s %s %s %s\n", timestamp, log_type, msg, pos);
#endif
        }

        if(_dessert_logflags & _DESSERT_LOGFLAG_RBUF) {
            pthread_rwlock_rdlock(&_dessert_logrbuf_len_lock);
            char* rbuf_line = _dessert_log_rbuf_nextline();

            if(rbuf_line != NULL) {
#if LOG_STYLE_OLD
                snprintf(rbuf_line, DESSERT_LOGLINE_MAX, "%s %s %s\n%80s\n", timestamp, log_type, msg, pos);
#else
                snprintf(rbuf_line, DESSERT_LOGLINE_MAX, "%s %s %s %s\n", timestamp, log_type, msg, pos);
#endif
            }

            pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
        }
    }
}

/**
 * Flush the messages to the log file
 *
 * @param data ignored
 * @param scheduled time when the callback should have been called
 * @param interval ignored
 *
 * @return DESSERT_PER_KEEP (do not unregister)
 */
dessert_per_result_t _dessert_flush_log(void* data, struct timeval* scheduled, struct timeval* interval) {
    if(_dessert_logfd != NULL) {
        pthread_mutex_lock(&_dessert_logfile_mutex);
        fflush(_dessert_logfd);
        pthread_mutex_unlock(&_dessert_logfile_mutex);
    }

#ifdef HAVE_LIBZ

    if(_dessert_logfdgz != NULL) {
        pthread_mutex_lock(&_dessert_logfile_mutex);
        int r = gzflush(_dessert_logfdgz, Z_SYNC_FLUSH);
        pthread_mutex_unlock(&_dessert_logfile_mutex);

        if(r != Z_OK) {
            dessert_warn("gzflush returned %d", r);
        }
    }

#endif
    dessert_debug("*** flushed log ***");
    return DESSERT_PER_KEEP;
}

/**
 * Modify the interval to flush the log file.
 * The log file is flushed every periode.
 *
 * @param argv[0] interval as string, "0" disables flushing
 */
int _dessert_cli_log_interval(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != 1) {
        cli_print(cli, "usage %s INTERVAL\n", command);
        return CLI_ERROR;
    }

    // disable
    if(_dessert_log_flush_periodic) {
        dessert_periodic_del(_dessert_log_flush_periodic);
        _dessert_log_flush_periodic = NULL;
    }

    uint8_t i = (uint8_t) strtoul(argv[0], NULL, 10);

    // enable
    if(i) {
        struct timeval interval;
        interval.tv_sec = i;
        interval.tv_usec = 0;
        struct timeval schedule;
        gettimeofday(&schedule, NULL);
        TIMEVAL_ADD(&schedule, i, 0);

        _dessert_log_flush_periodic = dessert_periodic_add(_dessert_flush_log, NULL, &schedule, &interval);
        cli_print(cli, "log flush interval set to %d seconds\n", i);
        dessert_notice("log flush interval set to %d seconds", i);
    }
    else {
        cli_print(cli, "log flushing disabled\n");
        dessert_notice("log flushing disabled");
    }

    return CLI_OK;
}

/** command "logging file" */
int _dessert_cli_logging_file(struct cli_def* cli, char* command, char* argv[], int argc) {
    FILE* newlogfd = NULL;
#ifdef HAVE_LIBZ
    gzFile* newlogfdgz = NULL;
    const char gz[] = ".gz";
#endif

    if(argc != 1) {
        cli_print(cli, "usage %s filename\n", command);
        return CLI_ERROR;
    }

#ifdef HAVE_LIBZ
    // see if the filename ends with ".gz"
    int len = strlen(argv[0]);
    int wrong_fext = strcmp(gz, argv[0] + len + 1 - sizeof(gz));

    /* enable compression if the deamon author set the corresponding flag
       or the filename ends on ".gz" */
    if((_dessert_logflags & _DESSERT_LOGFLAG_GZ)
       || !wrong_fext) {
        if(wrong_fext) {
            char newname[len+sizeof(gz)+1];
            snprintf(newname, len + sizeof(gz) + 1, "%s%s", argv[0], gz);
            newlogfdgz = gzopen(newname, "a");
        }
        else {
            newlogfdgz = gzopen(argv[0], "a");
        }
    }
    else
#endif
    {
        newlogfd = fopen(argv[0], "a");
    }

    if(newlogfd == NULL
#ifdef HAVE_LIBZ
       && newlogfdgz == NULL
#endif
      ) {
        dessert_err("failed to open %s as logfile", argv[0]);
        cli_print(cli, "failed to open %s as logfile", argv[0]);
        return CLI_ERROR;
    }

    /* clean up old logfile first */
    if(_dessert_logfd != NULL) {
        dessert_logcfg(DESSERT_LOG_NOFILE);
        fclose(_dessert_logfd);
    }

#ifdef HAVE_LIBZ

    if(_dessert_logfdgz != NULL) {
        dessert_logcfg(DESSERT_LOG_NOFILE);
        gzclose(_dessert_logfdgz);
    }

#endif

    if(newlogfd) {
        _dessert_logfd = newlogfd;
        dessert_logcfg(DESSERT_LOG_FILE | DESSERT_LOG_NOGZ);
    }

#ifdef HAVE_LIBZ

    if(newlogfdgz) {
        _dessert_logfdgz = newlogfdgz;
        dessert_logcfg(DESSERT_LOG_FILE | DESSERT_LOG_GZ);
    }

#endif
    return CLI_OK;
}

int _dessert_closeLogFile() {
    dessert_notice("closing log file");

    if(_dessert_log_flush_periodic) {
        dessert_periodic_del(_dessert_log_flush_periodic);
        _dessert_log_flush_periodic = NULL;
    }

    _dessert_flush_log(NULL, NULL, NULL);
    pthread_mutex_lock(&_dessert_logfile_mutex);
    dessert_logcfg(DESSERT_LOG_NOFILE);

    if(_dessert_logfd != NULL) {
        fclose(_dessert_logfd);
        _dessert_logfd = NULL;
    }

#ifdef HAVE_LIBZ

    if(_dessert_logfdgz != NULL) {
        gzclose(_dessert_logfdgz);
        _dessert_logfdgz = NULL;
    }

#endif
    pthread_mutex_unlock(&_dessert_logfile_mutex);
    return 0;
}

/** command "no logging file" */
int _dessert_cli_no_logging_file(struct cli_def* cli, char* command, char* argv[], int argc) {
    _dessert_closeLogFile();
    return CLI_OK;
}

/** command "logging ringbuffer" */
int _dessert_cli_logging_ringbuffer(struct cli_def* cli, char* command, char* argv[], int argc) {
    int newlen = -1;

    if(argc != 1 || (newlen = (int) strtol(argv[0], NULL, 10)) < 0) {
        cli_print(cli, "usage %s [buffer length]\n", command);
        return CLI_ERROR;
    }

    if(newlen == _dessert_logrbuf_len) {
        return CLI_OK;
    }

    if(newlen == 0) {
        cli_print(cli,
                  "will not set buffer length to 0 - use no logging ringbuffer instead\n");
        return CLI_ERROR;
    }

    pthread_rwlock_wrlock(&_dessert_logrbuf_len_lock);

    /* make logging buffer larger - easy if not ENOMEM*/
    if(newlen > _dessert_logrbuf_len) {
        _dessert_logrbuf = realloc(_dessert_logrbuf, newlen
                                   * DESSERT_LOGLINE_MAX * sizeof(char));

        if(_dessert_logrbuf == NULL) {
            _dessert_logrbuf_len = 0;
            _dessert_logrbuf_cur = 0;
        }
        else {
            _dessert_logrbuf_len = newlen;
        }

        dessert_logcfg(DESSERT_LOG_RBUF);
        /* make logging buffer smaller - pain in the ass */
    }
    else if(newlen < _dessert_logrbuf_len) {
        /* move current log buffer if needed */
        if(_dessert_logrbuf_cur > newlen) {
            memmove(_dessert_logrbuf, _dessert_logrbuf + (DESSERT_LOGLINE_MAX
                    *(_dessert_logrbuf_cur - newlen)), newlen
                    * DESSERT_LOGLINE_MAX * sizeof(char));
            _dessert_logrbuf_cur -= newlen;
        }

        _dessert_logrbuf = realloc(_dessert_logrbuf, newlen
                                   * DESSERT_LOGLINE_MAX * sizeof(char));

        if(_dessert_logrbuf == NULL) {
            _dessert_logrbuf_len = 0;
            _dessert_logrbuf_cur = 0;
        }
        else {
            _dessert_logrbuf_len = newlen;
        }
    }
    else {
        dessert_err("this never happens");
    }

    if(_dessert_logrbuf_used > _dessert_logrbuf_len - 1) {
        _dessert_logrbuf_used = _dessert_logrbuf_len - 1;
    }

    pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
    return CLI_OK;
}

/** command "no logging ringbuffer" */
int _dessert_cli_no_logging_ringbuffer(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(_dessert_logrbuf == NULL) {
        return CLI_OK;
    }
    else {
        pthread_rwlock_wrlock(&_dessert_logrbuf_len_lock);
        dessert_logcfg(DESSERT_LOG_NORBUF);
        free(_dessert_logrbuf);
        _dessert_logrbuf = NULL;
        _dessert_logrbuf_len = 0;
        _dessert_logrbuf_cur = 0;
        pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
        return CLI_OK;
    }
}

/** just a helper function */
static int _dessert_loglevel_to_string(uint8_t level, char* buffer, uint32_t len) {
    switch(level) {
        case LOG_TRACE:
            snprintf(buffer, len, "%s", "trace");
            break;
        case LOG_DEBUG:
            snprintf(buffer, len, "%s", "debug");
            break;
        case LOG_INFO:
            snprintf(buffer, len, "%s", "info");
            break;
        case LOG_NOTICE:
            snprintf(buffer, len, "%s", "notice");
            break;
        case LOG_WARNING:
            snprintf(buffer, len, "%s", "warning");
            break;
        case LOG_ERR:
            snprintf(buffer, len, "%s", "error");
            break;
        case LOG_CRIT:
            snprintf(buffer, len, "%s", "critical");
            break;
        case LOG_EMERG:
            snprintf(buffer, len, "%s", "emergency");
            break;
        default:
            return -1;
    }

    return 0;
}

int _dessert_cli_cmd_set_loglevel(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != 1) {
        cli_print(cli, "usage %s [debug, info, notice, warning, error, critical, emergency]", command);
        return CLI_ERROR;
    }

    if(strcmp(argv[0], "trace") == 0) {
        _dessert_loglevel = LOG_TRACE;
    }
    else if(strcmp(argv[0], "debug") == 0) {
        _dessert_loglevel = LOG_DEBUG;
    }
    else if(strcmp(argv[0], "info") == 0) {
        _dessert_loglevel = LOG_INFO;
    }
    else if(strcmp(argv[0], "notice") == 0) {
        _dessert_loglevel = LOG_NOTICE;
    }
    else if(strcmp(argv[0], "warning") == 0) {
        _dessert_loglevel = LOG_WARNING;
    }
    else if(strcmp(argv[0], "error") == 0) {
        _dessert_loglevel = LOG_ERR;
    }
    else if(strcmp(argv[0], "critical") == 0) {
        _dessert_loglevel = LOG_CRIT;
    }
    else if(strcmp(argv[0], "emergency") == 0) {
        _dessert_loglevel = LOG_EMERG;
    }
    else {
        cli_print(cli, "invalid loglevel specified: %s", argv[0]);
        dessert_warn("invalid loglevel specified: %s", argv[0]);
    }

    char buf[128];
    _dessert_loglevel_to_string(_dessert_loglevel, buf, sizeof(buf));
    cli_print(cli, "loglevel is set to \"%s\"", buf);
    dessert_notice("loglevel is set to \"%s\"", buf);

    return CLI_OK;
}

int _dessert_cli_cmd_show_loglevel(struct cli_def* cli, char* command, char* argv[], int argc) {
    char buf[128];
    _dessert_loglevel_to_string(_dessert_loglevel, buf, sizeof(buf));
    cli_print(cli, "loglevel is set to \"%s\"", buf);

    return CLI_OK;
}

/** command "show logging" */
int _dessert_cli_cmd_logging(struct cli_def* cli, char* command, char* argv[], int argc) {
    pthread_rwlock_rdlock(&_dessert_logrbuf_len_lock);
    int i = 0;
    int max = _dessert_logrbuf_len - 1;
    char* line;

    if(_dessert_logrbuf_len < 1) {
        cli_print(
            cli,
            "logging to ringbuffer is disabled - use \"logging ringbuffer [int]\" in config-mode first");
        pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);
        return CLI_ERROR;
    }

    if(argc == 1) {
        int max2 = (int) strtol(argv[0], NULL, 10);

        if(max2 > 0) {
            max = max2;
        }
    }

    /* where to start and print? */
    if(max > _dessert_logrbuf_used) {
        max = _dessert_logrbuf_used;
    }

    i = _dessert_logrbuf_cur - max - 1;

    if(i < 0) {
        i += _dessert_logrbuf_len;
    }

    while(max > 0) {
        i++;
        max--;

        if(i == _dessert_logrbuf_len) {
            i = 0;
        }

        line = _dessert_logrbuf + (DESSERT_LOGLINE_MAX * i);
        cli_print(cli, "%s", line);
    }

    pthread_rwlock_unlock(&_dessert_logrbuf_len_lock);

    return CLI_OK;
}
