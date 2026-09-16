rule Win_Trojan_W13_3
{
strings:
	$a0 = { 040103c18905b93e01905f8bd781ea3401b440cd21 }


condition:
	$a0
}