rule Win_Trojan_MZT_1
{
strings:
	$a0 = { 40b90200ba1001cd21b440b90200baf902cd21b440b90c00ba0401cd21c3b440b91800ba8a }


condition:
	$a0
}