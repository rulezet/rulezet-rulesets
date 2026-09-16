rule Win_Trojan_Quox_2
{
strings:
	$a0 = { b90200f3a5a113048bd0b106d3e0be00 }


condition:
	$a0
}