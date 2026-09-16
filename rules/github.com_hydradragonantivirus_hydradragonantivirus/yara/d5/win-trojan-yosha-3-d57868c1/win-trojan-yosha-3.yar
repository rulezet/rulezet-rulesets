rule Win_Trojan_Yosha_3
{
strings:
	$a0 = { 8db64400bf000157a5a5c3b44ccd214de90000fa33c08ed88ed0bb007c8be3be1304ff0cfcad }


condition:
	$a0
}