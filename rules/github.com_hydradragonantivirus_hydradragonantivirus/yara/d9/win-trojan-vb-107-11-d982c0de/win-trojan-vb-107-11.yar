rule Win_Trojan_VB_107_11
{
strings:
	$a0 = { 6c7567696e5f4b6579626f6113bc2e5c4f6d00727461071bf2f020312e33e99807 }


condition:
	$a0
}