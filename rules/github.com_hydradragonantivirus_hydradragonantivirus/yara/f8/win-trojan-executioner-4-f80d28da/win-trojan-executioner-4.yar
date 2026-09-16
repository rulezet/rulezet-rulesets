rule Win_Trojan_Executioner_4
{
strings:
	$a0 = { 0e1f0766b940020000bf8000be800066ad }


condition:
	$a0
}