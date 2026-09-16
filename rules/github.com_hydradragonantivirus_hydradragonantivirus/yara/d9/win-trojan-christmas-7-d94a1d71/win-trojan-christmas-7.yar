rule Win_Trojan_Christmas_7
{
strings:
	$a0 = { 03803ee603007405c606e70301803ee7030075288dbe00fd1657bfe6021e579aa906 }


condition:
	$a0
}