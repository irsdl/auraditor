/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.core;

import java.util.concurrent.*;
import java.util.List;
import java.util.ArrayList;
import javax.swing.Timer;

/**
 * Central thread manager to handle proper cleanup of all threads and timers
 */
public class ThreadManager {
    private static final List<Thread> managedThreads = new ArrayList<>();
    private static final List<Timer> managedTimers = new ArrayList<>();
    private static final List<CompletableFuture<?>> managedFutures = new ArrayList<>();
    private static final Object lock = new Object();
    private static volatile boolean shutdownRequested = false;

    /**
     * Register a thread for cleanup management
     */
    public static void registerThread(Thread thread) {
        synchronized (lock) {
            if (!shutdownRequested) {
                managedThreads.add(thread);
            }
        }
    }

    /**
     * Register a timer for cleanup management
     */
    public static void registerTimer(Timer timer) {
        synchronized (lock) {
            if (!shutdownRequested) {
                managedTimers.add(timer);
            }
        }
    }

    /**
     * Register a CompletableFuture for cleanup management
     */
    public static void registerFuture(CompletableFuture<?> future) {
        synchronized (lock) {
            if (!shutdownRequested) {
                managedFutures.add(future);
            }
        }
    }

    /**
     * Unregister a thread (called when thread completes normally)
     */
    public static void unregisterThread(Thread thread) {
        synchronized (lock) {
            managedThreads.remove(thread);
        }
    }

    /**
     * Unregister a timer (called when timer is stopped normally)
     */
    public static void unregisterTimer(Timer timer) {
        synchronized (lock) {
            managedTimers.remove(timer);
        }
    }

    /**
     * Unregister a future (called when future completes normally)
     */
    public static void unregisterFuture(CompletableFuture<?> future) {
        synchronized (lock) {
            managedFutures.remove(future);
        }
    }

    /**
     * Shutdown all managed threads, timers, and futures
     */
    public static void shutdown() {
        synchronized (lock) {
            shutdownRequested = true;

            // Stop all timers first
            for (Timer timer : new ArrayList<>(managedTimers)) {
                try {
                    if (timer.isRunning()) {
                        timer.stop();
                    }
                } catch (Exception e) {
                    // Ignore timer stop exceptions during shutdown
                }
            }
            managedTimers.clear();

            // Cancel all futures
            for (CompletableFuture<?> future : new ArrayList<>(managedFutures)) {
                try {
                    future.cancel(true);
                } catch (Exception e) {
                    // Ignore future cancellation exceptions
                }
            }
            managedFutures.clear();

            // Interrupt all threads
            for (Thread thread : new ArrayList<>(managedThreads)) {
                try {
                    if (thread.isAlive()) {
                        thread.interrupt();
                    }
                } catch (Exception e) {
                    // Ignore thread interrupt exceptions
                }
            }

            // Wait for threads to finish (with timeout)
            for (Thread thread : new ArrayList<>(managedThreads)) {
                try {
                    thread.join(500); // Wait max 500ms per thread
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            managedThreads.clear();
        }
    }

    /**
     * Create a managed thread that will be automatically cleaned up
     */
    public static Thread createManagedThread(Runnable runnable, String name) {
        Thread thread = new Thread(() -> {
            try {
                runnable.run();
            } finally {
                unregisterThread(Thread.currentThread());
            }
        }, name);
        registerThread(thread);
        return thread;
    }

    /**
     * Create a managed timer that will be automatically cleaned up
     */
    public static Timer createManagedTimer(int delay, java.awt.event.ActionListener listener) {
        Timer timer = new Timer(delay, listener);
        registerTimer(timer);
        return timer;
    }

    /**
     * Create a managed CompletableFuture that will be automatically cleaned up
     */
    public static <T> CompletableFuture<T> createManagedFuture(java.util.function.Supplier<T> supplier) {
        CompletableFuture<T> future = CompletableFuture.supplyAsync(supplier);
        registerFuture(future);
        future.whenComplete((result, throwable) -> unregisterFuture(future));
        return future;
    }

    /**
     * Create a managed CompletableFuture for runAsync that will be automatically cleaned up
     */
    public static CompletableFuture<Void> createManagedRunAsync(Runnable runnable) {
        CompletableFuture<Void> future = CompletableFuture.runAsync(runnable);
        registerFuture(future);
        future.whenComplete((result, throwable) -> unregisterFuture(future));
        return future;
    }

    /**
     * Get count of active managed resources (for debugging)
     */
    public static String getStatus() {
        synchronized (lock) {
            return String.format("Threads: %d, Timers: %d, Futures: %d",
                managedThreads.size(), managedTimers.size(), managedFutures.size());
        }
    }
}