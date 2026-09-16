rule Win_Spyware_Banker_3002
{
strings:
	$a0 = { 5020a115b1b33a9f9f39acd8291d9037417f685dbdb902c644120f93e3ce0780b9307e95e8109859b5e6d4b580 }


condition:
	$a0
}