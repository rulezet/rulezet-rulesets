rule Win_Downloader_Swizzor_320
{
strings:
	$a0 = { 8dd9d31a03e2f4eba3ee8cd124d33971e8bcdb74912c2c4d44135c631d82bcf9c0671345a00e4521af11042d4a60c9cdbdfbed2ef4514196c61c7e39f4fea413dece5d642700fba0dcd9145e }


condition:
	$a0
}