rule Win_Trojan_N_57
{
strings:
	$a0 = { 8edfbe007cff8c1388cd12b106d3e08ec0fa8ed78be687454ea3d57db8f00087454ca3d37d57 }


condition:
	$a0
}