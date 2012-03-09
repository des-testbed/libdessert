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

/* global data storage // P U B L I C */

/* global data storage // P R I V A T E */
static dessert_periodic_t* _tasklist = NULL;
static pthread_mutex_t _dessert_periodic_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _dessert_periodic_changed = PTHREAD_COND_INITIALIZER;
static pthread_t _dessert_periodic_worker;
static int _dessert_periodic_worker_running = 0;

/* local data storage*/
dessert_ptr2name_t* _dessert_func2name = NULL;

/* local functions forward declarations*/
static int _dessert_periodic_add_periodic_t(dessert_periodic_t* task);
static void* _dessert_periodic_thread(void* arg);

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * P E R I O D I C   T A S K S
 *
 ******************************************************************************/

/** Adds a delayed/periodic task to the task list
 *
 * @param[in] c callback to call when task is scheduled
 * @param[in] data data to give to the callback
 * @param[in] scheduled when should the callback be called the first time
 * @param[in] interval how often should it be called (set to NULL if only once)
 *
 * @retval pointer if the callback was added successfully
 * @retval NULL otherwise
 *
 * @note The <a href="http://www.gnu.org/s/libc/manual/html_node/Elapsed-Time.html#Elapsed-Time">GNU C Library Documentation</a>
 * states about the @c tv_usec member of the @c struct @c timeval: <em>This is the
 * rest of the elapsed time (a fraction of a second), represented as the number
 * of microseconds. It is always less than one @a million.</em> So, to make sure
 * this invariant is always met, consider using the provided TIMEVAL_ADD() macro.
 *
 * @par Description:
 *
 * @par Examples:
 * @li Register a callback function to be executed every 1.5 seconds - and
 * delay the first call to it for another 1.5 seconds:
 * @code
 *  struct timeval interval;
 *  interval.tv_sec = 1;
 *  interval.tv_usec = 500000;
 *
 *  struct timeval schedule;
 *  gettimeofday(&schedule, NULL);
 *  TIMEVAL_ADD(&schedule, 1, 500000);
 *
 *  dessert_periodic_add(callback, NULL, &schedule, &interval);
 * @endcode
 *
 *
 */
dessert_periodic_t* dessert_periodic_add(dessert_periodiccallback_t* c, void* data, const struct timeval* scheduled, const struct timeval* interval) {
    struct timeval now;
    dessert_periodic_t* task;

    if(scheduled == NULL) {
        gettimeofday(&now, NULL);
        scheduled = &now;
    }

    assert(scheduled != NULL);

    /* sanity checks */
    if(c == NULL) {
        return (NULL);
    }

    /* get task memory */
    task = malloc(sizeof(dessert_periodic_t));

    if(task == NULL) {
        return NULL;
    }

    /* copy data */
    task->c = c;
    task->data = data;
    memcpy(&(task->scheduled), scheduled, sizeof(struct timeval));

    if(interval == NULL) {
        task->interval.tv_sec = 0;
        task->interval.tv_usec = 0;
    }
    else {
        memcpy(&(task->interval), interval, sizeof(struct timeval));
    }

    task->next = NULL;

    pthread_mutex_lock(&_dessert_periodic_mutex);
    _dessert_periodic_add_periodic_t(task);
    pthread_mutex_unlock(&_dessert_periodic_mutex);

    return (task);
}

/** Adds a delayed task to the task list
 *
 * This is an easier version of dessert_periodic_add() taking a single delay as parameter.
 *
 * @param[in] c callback to call when task is scheduled
 * @param[in] data data to give to the callback
 * @param[in] delay the delay in seconds
 *
 * %DESCRIPTION: \n
 */
dessert_periodic_t* dessert_periodic_add_delayed(dessert_periodiccallback_t* c, void* data, int delay) {
    struct timeval at;
    gettimeofday(&at, NULL);
    at.tv_sec += delay;
    return (dessert_periodic_add(c, data, &at, NULL));
}

/** Removes a periodic task from the task list.
 *
 * @param[in] p pointer to task description
 * @param[in] data data pointer given to dessert_periodic_add*
 *
 * @return -1 on failure, 0 if the task was removed
 *
 * %DESCRIPTION: \n
 */
int dessert_periodic_del(dessert_periodic_t* p) {
    dessert_periodic_t* i;
    int x = -1;

    if(p == NULL) {
        dessert_warn("dessert_periodic_del was called with a NULL pointer....doing nothing!11!!");
        return 0;
    }

    pthread_mutex_lock(&_dessert_periodic_mutex);

    if(p == _tasklist) {
        _tasklist = _tasklist->next;
        x++;
    }

    i = _tasklist;

    while(i != NULL) {
        if(i->next == p) {
            i->next = p->next;
            x++;
        }

        i = i->next;
    }

    pthread_mutex_unlock(&_dessert_periodic_mutex);

    assert(x < 2);

    free(p);
    return x;
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * P E R I O D I C   T A S K S
 *
 ******************************************************************************/

/** internal function to start periodic worker */
void _dessert_periodic_init() {
    if(_dessert_periodic_worker_running == 0) {
        _dessert_periodic_worker_running = 1;
        pthread_create(&_dessert_periodic_worker, NULL,
                       _dessert_periodic_thread, NULL);
    }
}

/******************************************************************************
 *
 * LOCAL / PRIVATE
 *
 * P E R I O D I C   T A S K S
 *
 ******************************************************************************/

/* internal task list modifier - only call while holding _dessert_periodic_mutex */
static int _dessert_periodic_add_periodic_t(dessert_periodic_t* task) {
    dessert_periodic_t* i;

    /* first task? */
    if(_tasklist == task) {
        dessert_err("infinite loop in periodic tasklist requested - aborting!");
        return (-1);
    }
    else if(_tasklist == NULL) {
        _tasklist = task;
        pthread_cond_broadcast(&_dessert_periodic_changed);
    }
    /* is next task.... */
    else if(task->scheduled.tv_sec < _tasklist->scheduled.tv_sec
            || (task->scheduled.tv_sec == _tasklist->scheduled.tv_sec
                && task->scheduled.tv_usec < _tasklist->scheduled.tv_usec)) {
        task->next = _tasklist;
        _tasklist = task;
        pthread_cond_broadcast(&_dessert_periodic_changed);
    }
    /* search right place */
    else {
        i = _tasklist;

        while(i->next != NULL && (i->next->scheduled.tv_sec
                                  < task->scheduled.tv_sec || (i->next->scheduled.tv_sec
                                          == task->scheduled.tv_sec && i->next->scheduled.tv_usec
                                          <= task->scheduled.tv_usec))) {
            i = i->next;

            if(i->next == task) {
                dessert_err("infinite loop in periodic tasklist requested - aborting!");
                return (-1);
            }
        }

        /* last or right place */
        task->next = i->next;
        i->next = task;
        /* no need to tell periodic thread to check
        again - next task has not changed */
    }

    return 0;
}

/** Inserts a name in the function2name hash map
 *
 * @param ptr pointer to the function
 * @param name name of the function
 */
void dessert_register_ptr_name(void* ptr, const char* name) {
    dessert_ptr2name_t* f = (dessert_ptr2name_t*) malloc(sizeof(dessert_ptr2name_t));
    if(f == NULL) {
        dessert_crit("could not alloc memory");
        return;
    }
    char* s = malloc(strlen(name)+1);
    if(s == NULL) {
        free(f);
        dessert_crit("could not alloc memory");
        return;
    }
    f->ptr = ptr;
    strcpy(s, name);
    f->name = s;
    HASH_ADD_PTR(_dessert_func2name, ptr, f);
}

const char* dessert_ptr2name(void* ptr) {
    dessert_ptr2name_t* e;
    HASH_FIND_PTR(_dessert_func2name, &ptr, e);
    return (e == NULL ? NULL : e->name);
}

int _dessert_cmd_print_tasks(struct cli_def* cli, char* command, char* argv[], int argc) {
    pthread_mutex_lock(&_dessert_periodic_mutex);
    dessert_periodic_t* cur = _tasklist;
    uint16_t i = 0;
    cli_print(cli, "%4s\t%32s\t%16s\t%16s\t\%10s", "#", "function", "scheduled [s]", "interval [s]", "data");
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);
    double curtime = timestamp.tv_sec + timestamp.tv_usec/(1000.0*1000.0);
    while(cur) {
        const char* name = dessert_ptr2name(cur->c);
        if(name) {
            cli_print(cli, "%4d\t%32s\t%16.3f\t%16.3f\t\%10p",
                i,
                name,
                cur->scheduled.tv_sec + cur->scheduled.tv_usec/(1000.0*1000.0) - curtime,
                cur->interval.tv_sec + cur->interval.tv_usec/(1000.0*1000.0),
                cur->data
            );
        }
        else {
            cli_print(cli, "%4d\t%32p\t%16.3f\t%16.3f\t\%10p",
                i,
                cur->c,
                cur->scheduled.tv_sec + cur->scheduled.tv_usec/(1000.0*1000.0) - curtime,
                cur->interval.tv_sec + cur->interval.tv_usec/(1000.0*1000.0),
                cur->data
            );
        }
        cur = cur->next;
        i++;
    }
    pthread_mutex_unlock(&_dessert_periodic_mutex);
    return CLI_OK;
}

/* internal worker for the task list */
static void* _dessert_periodic_thread(void* arg) {
    dessert_periodic_t* next_task;
    dessert_periodic_t task;
    struct timeval now;
    struct timespec ts;

    pthread_mutex_lock(&_dessert_periodic_mutex);

    /* loops endless if no error */
    while(true) {
        // no tasks -> sleep
        if(_tasklist == NULL) {
            // sleep until task is added
            if(pthread_cond_wait(&_dessert_periodic_changed, &_dessert_periodic_mutex) == EINVAL) {
                dessert_err("sleeping failed in periodic scheduler - scheduler died");
                break;
            }

            continue;
        }
        // sleep until the next task has to be run
        else {
            gettimeofday(&now, NULL);
            if(now.tv_sec < _tasklist->scheduled.tv_sec
                || (now.tv_sec <= _tasklist->scheduled.tv_sec && now.tv_usec < _tasklist->scheduled.tv_usec)) {
                ts.tv_sec = _tasklist->scheduled.tv_sec;
                ts.tv_nsec = _tasklist->scheduled.tv_usec * 1000;

                if(pthread_cond_timedwait(&_dessert_periodic_changed, &_dessert_periodic_mutex, &ts) == EINVAL) {
                    dessert_err("sleeping failed in periodic scheduler - scheduler died");
                    break;
                }

                continue;
            }
        }

        /* run next task */
        next_task = _tasklist;
        _tasklist = next_task->next;

        /* save task to local variable */
        memcpy(&task, next_task, sizeof(dessert_periodic_t));

        /* periodic task - re-add */
        if(next_task->interval.tv_sec != 0 || next_task->interval.tv_usec != 0) {
            next_task->scheduled.tv_sec += next_task->interval.tv_sec;
            next_task->scheduled.tv_usec += next_task->interval.tv_usec;

            while(next_task->scheduled.tv_usec >= 1000000) {
                next_task->scheduled.tv_sec += 1;
                next_task->scheduled.tv_usec -= 1000000;
            }

            _dessert_periodic_add_periodic_t(next_task);
        }
        /* otherwise free memory */
        else {
            free(next_task);
        }

        /* run the callback */
        pthread_mutex_unlock(&_dessert_periodic_mutex);

        /* call the callback */
        if(task.c(task.data, &(task.scheduled), &(task.interval)) == DESSERT_PER_UNREGISTER) {
            dessert_periodic_del(next_task);
        }

        pthread_mutex_lock(&_dessert_periodic_mutex);
    }

    pthread_mutex_unlock(&_dessert_periodic_mutex);
    dessert_warn("task scheduler terminating");
    _dessert_periodic_worker_running = 0;
    return (NULL);
}

void dessert_timevaladd(struct timeval* tv, uint32_t sec, uint32_t usec) {
    tv->tv_sec  += sec;
    tv->tv_usec += usec;
    while(tv->tv_usec >= 1000000) {
        tv->tv_sec++;
        tv->tv_usec -= 1000000;
    }
}

void dessert_timevaladd2(struct timeval* result, struct timeval* tva, struct timeval* tvb) {
    result->tv_sec  = tva->tv_sec + tva->tv_sec;
    result->tv_usec = tva->tv_usec + tva->tv_usec;
    while(result->tv_usec >= 1000000) {
        result->tv_sec++;
        result->tv_usec -= 1000000;
    }
}

/** Return ms stored in a timeval struct
 *
 * @param time data structure to evaluate
 * @return time in ms
 */
uint32_t dessert_timeval2ms(struct timeval* time) {
    return time->tv_sec*1000 + time->tv_usec/1000;
}

/** Fill timeval struct with a given time in ms
 *
 * @param ms time in ms to write into timeval struct
 * @param time timeval struct to fill
 */
void dessert_ms2timeval(uint32_t ms, struct timeval* time) {
    time->tv_sec = ms/1000;
    time->tv_usec = (ms%1000) * 1000;
}

/** Current time as timestamp in ms
 *
 * @return current time in ms
 */
uint32_t dessert_cur_ms() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return dessert_timeval2ms(&t);
}
