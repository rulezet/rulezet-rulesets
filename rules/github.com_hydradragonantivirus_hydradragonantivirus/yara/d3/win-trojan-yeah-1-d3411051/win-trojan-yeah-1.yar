rule Win_Trojan_Yeah_1
{
strings:
	$a0 = { 8edb8ed3bc007cfba1130483e805a31304b106d3e08ec0b80902b90200ba8000cd13bb7c01 }


condition:
	$a0
}