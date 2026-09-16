rule Win_Trojan_Druidic_1
{
strings:
	$a0 = { babb02b80125cd21b003cd21ba????b80125cd21b001cd21b44732d2be????cd21ba????b44ecd217303 }


condition:
	$a0
}