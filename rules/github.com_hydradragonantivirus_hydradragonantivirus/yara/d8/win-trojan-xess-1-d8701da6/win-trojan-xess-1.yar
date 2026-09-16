rule Win_Trojan_Xess_1
{
strings:
	$a0 = { 83ec086a00ff35c4ca0408e824faffff83c4108985e0eeffff83bde0eeffffff751a83ec0c6800a30408e8c5f8ffff83c41083ec0c6affe818faffff }

	$a1 = { 3b33316d461b5b303b33316d6c6f6f64696e671b5b }


condition:
	$a0 and $a1
}