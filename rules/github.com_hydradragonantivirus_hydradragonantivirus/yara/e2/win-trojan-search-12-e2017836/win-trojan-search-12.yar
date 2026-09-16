rule Win_Trojan_Search_12
{
strings:
	$a0 = { e800005d83ed065555bb1601bf7100b98c002e311b471eb860008ed8891e0700bb34128b1e07001f90e5428bf0 }


condition:
	$a0
}