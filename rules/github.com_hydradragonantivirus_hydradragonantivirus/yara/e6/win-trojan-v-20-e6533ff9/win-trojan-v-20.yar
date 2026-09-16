rule Win_Trojan_V_20
{
strings:
	$a0 = { d88ed0bc00f0fba113042d0300a31304b106d3e02d10008ec006b8de04500e1fbebe7db304 }


condition:
	$a0
}