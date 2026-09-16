rule Win_Downloader_Banload_958
{
strings:
	$a0 = { ba69d7854bdfb7f6ab4d8ede0d526609d16257dc23399fb5100de850d180837f700b16aa6136622d2f6dddcb81d4145aa19d6f8cc59f22b14fdd408e556f11ab24c59c5b078b07d1c6ee206586ab }


condition:
	$a0
}