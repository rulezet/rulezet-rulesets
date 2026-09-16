rule Win_Downloader_Small_2063
{
strings:
	$a0 = { 687423703a2f8b75a964618d3a2e6d349c30739e66fd78eff12f4f }


condition:
	$a0
}