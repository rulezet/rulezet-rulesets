rule Win_Downloader_Adload_23
{
strings:
	$a0 = { c745fc01000000c745fc02000000c78528feffff741c4000c78520feffff080000008d9520feffff8d4da0ff15a8104000 }


condition:
	$a0
}