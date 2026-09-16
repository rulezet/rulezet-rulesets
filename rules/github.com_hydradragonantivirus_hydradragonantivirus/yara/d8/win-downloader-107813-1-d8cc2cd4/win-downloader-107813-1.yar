rule Win_Downloader_107813_1
{
strings:
	$a0 = { 33c00bc1928bc823c89268655cf04068c3caa6415a58686e838d286851fa925ee80557ff }


condition:
	$a0
}