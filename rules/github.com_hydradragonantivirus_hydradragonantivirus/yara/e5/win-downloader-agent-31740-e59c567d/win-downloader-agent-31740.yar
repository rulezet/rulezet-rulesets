rule Win_Downloader_Agent_31740
{
strings:
	$a0 = { 8b95a0feffff8d45f0b940564000e8000028a08b45f0e800004030 }


condition:
	$a0
}