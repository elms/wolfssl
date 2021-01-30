#include <deos.h>
#include <printx.h>
#include <time.h>

#include <wolfcrypt/test/test.h>

int main(void)
{

  initPrintx("wolfSSL-test");
  printx("wolfSSL\n");
  for (int i=0; i< 1000; i++) {
	    printx("Current Loop Count       = %x (%d)\n", i, i);
	    waitUntilNextPeriod();
  }


  // taken from hello-world-timer.cpp
  struct tm starttime = { 0, 30, 12, 1, 12, 2020-1900, 0, 0, 0 };
  	  // startdate: July 1 2019, 12:30:00
  struct timespec ts_date;
  ts_date.tv_sec  = mktime(&starttime);
  ts_date.tv_nsec = 0LL;
  int res1 = clock_settime(CLOCK_REALTIME, &ts_date);
  	  // this will only take effect, if time-control is set in the xml-file
  	  // if not, Jan 1 1970, 00:00:00 will be the date


  time_t blah;
  time(&blah);

  int res = wolfcrypt_test(NULL);

  if (res == 0) {
	  printx("wolfcrypt Test Passed\n");
  }
  else {
	  printx("wolfcrypt Test Failed: %d\n", res);
  }

  while (1) {
	    waitUntilNextPeriod();
  }

  return 0;
}
