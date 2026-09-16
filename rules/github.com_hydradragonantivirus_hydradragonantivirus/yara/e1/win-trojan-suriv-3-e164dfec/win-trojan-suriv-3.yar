rule Win_Trojan_Suriv_3
{
strings:
	$a0 = { 8104bc81041e0783c30fd1ebd1ebd1ebd1eb891e0d01cd }


condition:
	$a0
}