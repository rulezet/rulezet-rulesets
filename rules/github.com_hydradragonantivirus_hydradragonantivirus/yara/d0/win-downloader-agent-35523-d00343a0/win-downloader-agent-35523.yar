rule Win_Downloader_Agent_35523
{
strings:
	$a0 = { eb1066623a432b2b484f4f4b90e998704e00a1 }

	$a1 = { 460656495255532e657865 }


condition:
	$a0 and $a1
}