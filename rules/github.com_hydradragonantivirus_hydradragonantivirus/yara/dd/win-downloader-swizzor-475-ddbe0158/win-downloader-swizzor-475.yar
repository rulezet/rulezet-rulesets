rule Win_Downloader_Swizzor_475
{
strings:
	$a0 = { 593f100373a06e8bddcd59f0ab775faae73c899c45c12e823d37de41b43a5b4907ae32fbd17b2073a8d2e7216686f8a52c71255b0af92fb5c85e9fa2e0553638fdb4af4535a22075becd083aa5c37b87 }


condition:
	$a0
}