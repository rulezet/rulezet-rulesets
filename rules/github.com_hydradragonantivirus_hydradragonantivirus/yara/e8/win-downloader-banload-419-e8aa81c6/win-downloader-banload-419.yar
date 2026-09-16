rule Win_Downloader_Banload_419
{
strings:
	$a0 = { 5568b980400064ff30648920b8b4a84000bad0804000e8bcb6ffffb8b0a84000e85eb6ffff }


condition:
	$a0
}