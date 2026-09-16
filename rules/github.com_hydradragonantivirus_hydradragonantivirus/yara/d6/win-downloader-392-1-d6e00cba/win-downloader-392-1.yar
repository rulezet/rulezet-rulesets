rule Win_Downloader_392_1
{
strings:
	$a0 = { 395db48d45c8508d8540ffffff74068d8560ffffff508d854cfbffff686040400050ff153030400083c410685c4040008d85dcfdffff50ffd78d85dcfeffff508d85dcfdffff50ffd6 }


condition:
	$a0
}