rule Win_Trojan_Mr_2
{
strings:
	$a0 = { 04cede7451a11304c7066704cede48a3130492b106 }


condition:
	$a0
}