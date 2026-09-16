rule Win_Downloader_19297_1
{
strings:
	$a0 = { 6a0068608840008d55e4b870884000e870fdffffff75e468cc8840008d55e0b8d8884000e85bfdffff }


condition:
	$a0
}