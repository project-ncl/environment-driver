package org.jboss.pnc.environmentdriver.enums;

import static org.jboss.pnc.environmentdriver.Driver.ERROR_MESSAGE_INTRO;
import static org.jboss.pnc.environmentdriver.Driver.ERROR_MESSAGE_INITIALIZATION;
import static org.jboss.pnc.environmentdriver.Driver.ERROR_MESSAGE_INVALID_IMAGE_NAME;
import static org.jboss.pnc.environmentdriver.Driver.ERROR_MESSAGE_REGISTRY;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import lombok.Getter;

@Getter
public enum PodErrorStatuses {

    /**
     * From: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
     *
     * ErrImagePull and ImagePullBackOff added to that list. The pod.getStatus() call will return the *reason* of
     * failure, and if the reason is not available, then it'll return the regular status (as mentioned in the link)
     *
     * For pod creation, the failure reason we expect when docker registry is not behaving is 'ErrImagePull' or
     * 'ImagePullBackOff'
     *
     * 'Error' and 'InvalidImageName' statuses were added as per NCL-6032 investigations
     */

    FAILED("Failed", true),
    UNKNOWN("Unknown", true),
    CRASHLOOPBACKOFF("CrashLoopBackOff", true),
    ERRIMAGEPULL("ErrImagePull", true, ERROR_MESSAGE_INTRO + ERROR_MESSAGE_REGISTRY),
    IMAGEPULLBACKOFF("ImagePullBackOff", true, ERROR_MESSAGE_INTRO + ERROR_MESSAGE_REGISTRY),
    ERROR("Error", true),
    CONTAINERCANNOTRUN("ContainerCannotRun", true),
    INVALIDIMAGENAME("InvalidImageName", false, ERROR_MESSAGE_INTRO + ERROR_MESSAGE_INVALID_IMAGE_NAME);

    private final String status;
    private final boolean retryable;
    private final String customErrMsg;

    private PodErrorStatuses(String status, boolean retryable) {
        this.status = status;
        this.retryable = retryable;
        this.customErrMsg = ERROR_MESSAGE_INTRO + ERROR_MESSAGE_INITIALIZATION;
    }

    private PodErrorStatuses(String status, boolean retryable, String customErrMsg) {
        this.status = status;
        this.retryable = retryable;
        this.customErrMsg = customErrMsg;
    }

    public static Optional<PodErrorStatuses> getIfPresent(String status) {
        return Arrays.stream(PodErrorStatuses.values())
                .filter(podStatuses -> status.equals(podStatuses.getStatus()))
                .findFirst();
    }

    public static Optional<PodErrorStatuses> getIfPresent(Set<String> containerStatuses) {
        return Arrays.stream(PodErrorStatuses.values())
                .filter(podStatuses -> containerStatuses.contains(podStatuses.getStatus()))
                .findFirst();
    }
}
