package org.jboss.pnc.environmentdriver.invokerserver;

import jakarta.servlet.Servlet;

import io.undertow.servlet.api.InstanceFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class ServletDeployment {
    private Class<? extends Servlet> aClass;
    private InstanceFactory<? extends Servlet> instanceFactory;
    private String mapping;

    public ServletDeployment(Class<? extends Servlet> aClass, InstanceFactory<? extends Servlet> instanceFactory) {
        this(aClass, instanceFactory, null);
    }

    public ServletDeployment(
            Class<? extends Servlet> aClass,
            InstanceFactory<? extends Servlet> instanceFactory,
            String mapping) {
        this.aClass = aClass;
        this.instanceFactory = instanceFactory;
        if (mapping == null) {
            this.mapping = aClass.getSimpleName();
        } else {
            this.mapping = mapping;
        }
    }

    public Class<? extends Servlet> getaClass() {
        return aClass;
    }

    public InstanceFactory<? extends Servlet> getInstanceFactory() {
        return instanceFactory;
    }

    public String getMapping() {
        return mapping;
    }
}
