rule Win_Trojan_Adinf_1
{
strings:
	$a0 = { 9a00005f005589e531c09a30055f00bf7b040e57e8c0fe5d31c09a16015f000000000000558bec83ec501ec5760c8d7e }


condition:
	$a0
}