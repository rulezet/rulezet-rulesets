rule Win_Downloader_Banload_83
{
strings:
	$a0 = { e855feffff6a006a008d45f08b0dbc5040008b1578654000e8cdefffff8b45f0e839f0ffff508d45ec8b0db85040008b15c0504000e8b0efffff8b45ece81cf0ffff506a00e8d0fdffff }


condition:
	$a0
}