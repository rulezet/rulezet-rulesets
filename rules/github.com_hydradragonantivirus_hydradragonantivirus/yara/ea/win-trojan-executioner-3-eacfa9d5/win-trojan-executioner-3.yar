rule Win_Trojan_Executioner_3
{
strings:
	$a0 = { 060e0e1f0766b901020000bf8000be800066ad }


condition:
	$a0
}