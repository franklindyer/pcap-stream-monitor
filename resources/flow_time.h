#include <time.h>

float timespec_diff(struct timespec t1, struct timespec t0) {
  double sec_diff = difftime(t1.tv_sec, t0.tv_sec);
  long nsec_diff = t1.tv_nsec - t0.tv_nsec;
  return ((float)sec_diff + ((float)nsec_diff)/1000000000);
}

struct timespec timespec_now() {
  struct timespec now;
  timespec_get(&now, TIME_UTC);
  return now;
}
