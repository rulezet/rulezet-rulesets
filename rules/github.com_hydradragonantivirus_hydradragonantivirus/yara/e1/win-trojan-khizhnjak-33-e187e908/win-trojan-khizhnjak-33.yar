rule Win_Trojan_Khizhnjak_33
{
strings:
	$a0 = { 03e91801baf802b8023dcd217305beb00256c3a30903ba0e038b1e0903b90300b43fcd2173 }


condition:
	$a0
}