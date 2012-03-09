/* Copyright (C) 2003, 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Martin Schwidefsky <schwidefsky@de.ibm.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */
/* Adapted to Android from GLIBC 2.11.1 by Ramin Baradari (C) 2010 */   
   
#include <errno.h>

#include "pthreadex.h"

/* Check whether rwlock prefers readers.   */
#define PTHREAD_RWLOCK_PREFER_READER_P(rwlock) ((rwlock)->__flags == 0)

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
    int result = 0;

    /* Make sure we are along.  */
    pthread_mutex_lock(&rwlock->__lock_mutex);

    while (1) {
        /* Get the rwlock if there is no writer...  */
        if (rwlock->__writer_thread == 0
                /* ...and if either no writer is waiting or we prefer readers.  */
                && (!rwlock->__nr_writers_queued
                || PTHREAD_RWLOCK_PREFER_READER_P(rwlock))) {
            /* Increment the reader counter.  Avoid overflow.  */
            if (__builtin_expect(++rwlock->__nr_readers_active == 0, 0)) {
                /* Overflow on number of readers.	 */
                --rwlock->__nr_readers_active;
                result = EAGAIN;
            }
            break;
        }

        /* Make sure we are not holding the rwlock as a writer.  This is
        a deadlock situation we recognize and report.  */
        if (__builtin_expect(rwlock->__writer_thread == pthread_self(), 0)) {
            result = EDEADLK;
            break;
        }

        /* Remember that we are a reader.  */
        if (__builtin_expect(++rwlock->__nr_readers_queued == 0, 0)) {
            /* Overflow on number of queued readers.  */
            --rwlock->__nr_readers_queued;
            result = EAGAIN;
            break;
        }

        /* Wait for the writer to finish.  */
        pthread_cond_wait(&rwlock->__wait_cond, &rwlock->__lock_mutex);

		/* To start over again, remove the thread from the reader list.  */
        --rwlock->__nr_readers_queued;
    }

    /* We are done, free the lock.  */
    pthread_mutex_unlock(&rwlock->__lock_mutex);

    return result;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
    int result = 0;

    /* Make sure we are along.  */
    pthread_mutex_lock(&rwlock->__lock_mutex);

    while (1) {
        /* Get the rwlock if there is no writer and no reader.  */
        if (rwlock->__writer_thread == 0 && rwlock->__nr_readers_active == 0) {
            /* Mark self as writer.  */
            rwlock->__writer_thread = pthread_self();
            break;
        }

        /* Make sure we are not holding the rwlock as a writer.  This is
        a deadlock situation we recognize and report.  */
        if (__builtin_expect(rwlock->__writer_thread == pthread_self(), 0)) {
            result = EDEADLK;
            break;
        }

        /* Remember that we are a writer.  */		
        if (__builtin_expect(++rwlock->__nr_writers_queued == 0, 0)) {
            /* Overflow on number of queued writers.  */
            --rwlock->__nr_writers_queued;
            result = EAGAIN;
            break;
        }

        /* Wait for the writer or reader(s) to finish.  */
        pthread_cond_wait(&rwlock->__wait_cond, &rwlock->__lock_mutex);

        /* To start over again, remove the thread from the writer list.  */
        --rwlock->__nr_writers_queued;
    }

    /* We are done, free the lock.  */
    pthread_mutex_unlock(&rwlock->__lock_mutex);

    return result;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
    pthread_mutex_lock(&rwlock->__lock_mutex);
	
    if (rwlock->__writer_thread != 0)
        rwlock->__writer_thread = 0;
    else
        --rwlock->__nr_readers_active;
	
    // if there are still active readers then there is no need to wake up anyone else
    if (rwlock->__nr_readers_active == 0) {
	    pthread_mutex_unlock(&rwlock->__lock_mutex);
		pthread_cond_broadcast(&rwlock->__wait_cond);
	    return 0;
    } else {
	    pthread_mutex_unlock(&rwlock->__lock_mutex);
	}	
    
    return 0;
}
