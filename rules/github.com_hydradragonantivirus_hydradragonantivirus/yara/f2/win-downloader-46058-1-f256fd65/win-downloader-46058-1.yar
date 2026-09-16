rule Win_Downloader_46058_1
{
strings:
	$a0 = { 558bec515153 }

	$a1 = { 531c03532039d6740748b0377702b0332b }


condition:
	$a0 and $a1
}