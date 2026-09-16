rule Win_Trojan_DelTree_10
{
strings:
	$a0 = { 64656c74726565202f7920633a5c2a2e2a }


condition:
	$a0
}