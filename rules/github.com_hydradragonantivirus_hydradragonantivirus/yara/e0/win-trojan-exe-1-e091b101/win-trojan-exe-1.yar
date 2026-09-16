rule Win_Trojan_Exe_1
{
strings:
	$a0 = { 81ed0300b8dd4bcd213d4bdd74671eb44abbffffcd2183eb23b44acd21b448bb2200cd210e1f8ec0be000003f533ff }


condition:
	$a0
}