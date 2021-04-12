package org.jboss.pnc.environmentdriver;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class Constants {

    public static final String METRICS_POD_STARTED_KEY = "openshift-environment-driver.started.pod";
    public static final String METRICS_POD_STARTED_ATTEMPTED_KEY = METRICS_POD_STARTED_KEY + ".attempts"; // TODO
    public static final String METRICS_POD_STARTED_SUCCESS_KEY = METRICS_POD_STARTED_KEY + ".success";
    public static final String METRICS_POD_STARTED_FAILED_KEY = METRICS_POD_STARTED_KEY + ".failed";
    public static final String METRICS_POD_STARTED_RETRY_KEY = METRICS_POD_STARTED_KEY + ".retries"; // TODO
    public static final String METRICS_POD_STARTED_FAILED_REASON_KEY = METRICS_POD_STARTED_KEY + ".failed_reason";

}
