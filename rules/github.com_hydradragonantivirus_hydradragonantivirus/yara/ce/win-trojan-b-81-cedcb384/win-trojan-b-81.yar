rule Win_Trojan_B_81
{
strings:
	$a0 = { c08ed88ed0bcf0fffb33db8b8713042d020089871304b106d3e08ec08b474c8987b4018b474e }


condition:
	$a0
}