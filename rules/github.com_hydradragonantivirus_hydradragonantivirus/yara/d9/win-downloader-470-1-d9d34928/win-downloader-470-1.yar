rule Win_Downloader_470_1
{
strings:
	$a0 = { c86898e96ae0dea11d9d297db14d2b3fc70b0bb5c751e6b07af977d463e48932eafab7cd3c040452741a12d5f5981dbcb4e8b8c5a343190dc94a3e96b2e94ad6b6dd679872272daa9c37221d2bc4 }


condition:
	$a0
}