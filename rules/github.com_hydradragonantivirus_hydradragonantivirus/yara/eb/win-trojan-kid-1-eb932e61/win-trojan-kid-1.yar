rule Win_Trojan_Kid_1
{
strings:
	$a0 = { 40b989018bd681eaa701cd21cc582d03008bfe83ef35890583ef01b80042b90000ba0000cd21b4 }


condition:
	$a0
}