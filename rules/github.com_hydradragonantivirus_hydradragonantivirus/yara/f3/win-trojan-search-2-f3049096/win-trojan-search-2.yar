rule Win_Trojan_Search_2
{
strings:
	$a0 = { 5e803cb8743d33c933d2b80042cd21832e09010dba0001 }


condition:
	$a0
}