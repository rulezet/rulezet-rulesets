rule Win_Trojan_I13_21
{
strings:
	$a0 = { 1acd21b44e33c9bab001cd217368b41aba8000cd21a12c00a3b6018c0eba018c0ebe018c0ec2018e062c00bf }


condition:
	$a0
}