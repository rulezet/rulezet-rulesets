rule Win_Trojan_Druid_8
{
strings:
	$a0 = { 02ebfcba0602b80125cd21b003cd21ba0602b80125cd21b001cd21b44732d2be1102cd21ba0702b44ecd217303eb }


condition:
	$a0
}