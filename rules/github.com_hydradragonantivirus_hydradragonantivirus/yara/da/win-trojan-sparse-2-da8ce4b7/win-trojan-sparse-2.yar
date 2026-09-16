rule Win_Trojan_Sparse_2
{
strings:
	$a0 = { 76b82135cd21b0eaa20002891e01028c }


condition:
	$a0
}