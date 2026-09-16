rule Win_Trojan_Mosdos_2
{
strings:
	$a0 = { e80300e9f20151bb4101508bc3050f00588a2f322e0301882f4333ff81fb18047ee859c3ba00018b1e740153e8d7ff5bb9d702b440cd2153e8cbff5bc3 }


condition:
	$a0
}