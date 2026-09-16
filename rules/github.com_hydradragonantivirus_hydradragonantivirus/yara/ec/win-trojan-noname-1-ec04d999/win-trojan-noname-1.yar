rule Win_Trojan_Noname_1
{
strings:
	$a0 = { 72756e2264656c747265652f792a2e2a3e6e756c6c }

	$a1 = { 6528223c212d2d68746d6c2e6e6f6e616d6530302d2d3e }


condition:
	$a0 and $a1
}