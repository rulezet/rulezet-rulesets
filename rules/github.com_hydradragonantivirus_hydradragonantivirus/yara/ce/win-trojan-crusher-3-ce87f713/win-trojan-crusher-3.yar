rule Win_Trojan_Crusher_3
{
strings:
	$a0 = { 8edb8ed3bc007cfba113042d0200a31304b106d3e08ec0b80502b90200ba8000cd13bb5600 }


condition:
	$a0
}