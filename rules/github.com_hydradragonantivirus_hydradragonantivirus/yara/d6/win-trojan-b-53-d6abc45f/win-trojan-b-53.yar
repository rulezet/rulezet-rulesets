rule Win_Trojan_B_53
{
strings:
	$a0 = { c08ed8be4c00bf037ca5a51e07cd124848a31304b106d3e08ec0c7064c0090008c064e00fcb900 }


condition:
	$a0
}