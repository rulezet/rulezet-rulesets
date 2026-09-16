rule Win_Trojan_Pysk_1
{
strings:
	$a0 = { 1301b4aacd2180fcbb7503e999001e06b82135cd211e0e1f8c840902899c0702b80935cd218c841302899c1102 }


condition:
	$a0
}