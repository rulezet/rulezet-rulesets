rule Win_Trojan_TinyFamily3_1
{
strings:
	$a0 = { 81ee0b018baca00181c503018d94a201 }


condition:
	$a0
}