rule Win_Trojan_Hob_2
{
strings:
	$a0 = { 8bf4fb56ff0e1304cd12b106d3e050bb1d018ec0b90001f3a553cb50e4403ca072fa3cc077 }


condition:
	$a0
}