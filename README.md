# HULApp
HULApp is an application-aware in-network load balancer. It is built on top of HULA: the recent in-network load-balancer for programmable data planes. HULApp uses two different congestion metrics (queue depth and path utilization) to load-balance two general groups of applications separately: those which are more sensitive to latency and those which are less so. 
