rule Win_Trojan_Anarchy_5
{
strings:
	$a0 = { 78b99d0162b2df31d8469ae226b8dc5711218d526840669cdfb94602112164009e99f7c911216840 }


condition:
	$a0
}