rule Win_Trojan_Rewin_3
{
strings:
	$a0 = { 316b985f40bb944952130736fa01a3ffff4ffe526577696e64ffcc3100026af3044aefb90644ac4de62168ffffffff4d254faa917f66e56ee348b33ecbb4473935cb3a4fad339966cf11b7 }


condition:
	$a0
}