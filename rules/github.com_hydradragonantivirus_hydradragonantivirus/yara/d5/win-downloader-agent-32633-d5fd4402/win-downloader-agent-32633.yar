rule Win_Downloader_Agent_32633
{
strings:
	$a0 = { 6f00642e636f6d0e2f6361eaedb1f66c632e62432b5c742518657865ffdffe178236343546424344 }


condition:
	$a0
}