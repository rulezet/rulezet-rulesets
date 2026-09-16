rule Win_Trojan_SillyOC_28
{
strings:
	$a0 = { 02ebfcbaac01b80125cd21b003cd21baac01b80125cd21b001cd21b44732d2beb701cd21baad01b44ecd217303eb }


condition:
	$a0
}