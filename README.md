# PNC Environment driver

Environment driver provides REST endpoints to create and destroy Openshift objects required for the "build environment" (a build in a pod).

A `/create` endpoint is a "pass-through" endpoint, it responds when all remote requests complete.
If any of the remote requests fail the response from the environment driver is an error response.
If the requests to Openshift are success the driver starts to monitor pod availability and makes are callback to the invoker when the pod is ready.

The `/complete` responds immediately, and the driver tries to destroy the environment (no guarantee). 
In case the "debug environment" is requested the endpoint returns when the debug is enabled.
   
The `/cancel` endpoint responds immediately, and the driver tries to destroy the environment (no guarantee).
In case of multiple driver instances the "sticky session" should be used to make the `/cancel` request hit the same node as the `/create` one to cancel the internal monitor. 