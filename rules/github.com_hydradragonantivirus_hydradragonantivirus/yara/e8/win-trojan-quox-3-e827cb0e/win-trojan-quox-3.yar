rule Win_Trojan_Quox_3
{
strings:
	$a0 = { 8bd0b106d3e0be007c33ff8ec0b90b00f3a674072d4000ff0e1304fac7064c00 }


condition:
	$a0
}