rule Win_Trojan_Vlad_6
{
strings:
	$a0 = { 583dedfe7403e94401b8defacfe9a402e97302e99d01 }


condition:
	$a0
}