rule Win_Trojan_Wildy_5
{
strings:
	$a0 = { 2acd213c05751780fa0d7512b80013bd3902bb8c00ba160db9240090cd1006cd12b106d3e08ec026803e5d02577442 }


condition:
	$a0
}