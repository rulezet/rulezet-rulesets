rule Win_Trojan_Ngkoen_1
{
strings:
	$a0 = { db1df3ab4646ebe3b616b40231db8edbcd10e93d014848a31304b106d3e0a30f7c8ec0b903020e }


condition:
	$a0
}