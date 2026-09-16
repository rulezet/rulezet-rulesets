rule Win_Trojan_Stoned_67
{
strings:
	$a0 = { 8ed08ed8bc0050fba14c00a3077ca14e00a3097ca113042d0200a31304b8809f8ec0be007cbf0001b9be01fcf3 }


condition:
	$a0
}