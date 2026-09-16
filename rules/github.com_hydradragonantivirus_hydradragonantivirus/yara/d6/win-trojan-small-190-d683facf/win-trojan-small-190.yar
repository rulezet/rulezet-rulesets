rule Win_Trojan_Small_190
{
strings:
	$a0 = { 8cc08701ab0e1f0e075f2bcef3a4ebd4608bf2ac3de940750b1e0e1f99b9420090cd211f61 }


condition:
	$a0
}