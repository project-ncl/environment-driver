package org.jboss.pnc.environmentdriver;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Keep a set of active monitors per key (pod name)
 *
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@ApplicationScoped
public class ActiveMonitors {

    private Map<String, Set<CompletableFuture>> monitors = new ConcurrentHashMap<>();

    public void add(String key, CompletableFuture future) {
        Set<CompletableFuture> futures = monitors.computeIfAbsent(key, (k) -> new HashSet<>());
        futures.add(future);
    }

    public Set<CompletableFuture> get(String key) {
        return monitors.get(key);
    }

    public void remove(String key) {
        monitors.remove(key);
    }

    public void cancel(String key) {
        Set<CompletableFuture> futures = monitors.remove(key);
        if (futures != null) {
            futures.forEach(f -> f.cancel(false));
        }
    }
}
