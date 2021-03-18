package org.jboss.pnc.environmentdriver;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import javax.enterprise.context.ApplicationScoped;

import io.vertx.core.impl.ConcurrentHashSet;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
@ApplicationScoped
public class ActiveMonitors {

    private Map<String, Set<CompletableFuture>> monitors = new HashMap<>();

    public void add(String key, CompletableFuture<Void> future) {
        Set<CompletableFuture> futures = monitors.computeIfAbsent(key, (k) -> new ConcurrentHashSet<>());
        futures.add(future);
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
