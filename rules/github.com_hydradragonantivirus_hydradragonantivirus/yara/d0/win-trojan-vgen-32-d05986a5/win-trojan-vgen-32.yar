rule Win_Trojan_Vgen_32
{
strings:
	$a0 = { baac0233c9b8023ccd2193b440b92600ba8502cd21b43ecd21bae20233c9b8023ccd2193b440b92600babb02cd21 }


condition:
	$a0
}