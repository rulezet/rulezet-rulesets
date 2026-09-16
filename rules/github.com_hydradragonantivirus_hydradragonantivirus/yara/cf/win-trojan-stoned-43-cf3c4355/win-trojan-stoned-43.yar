rule Win_Trojan_Stoned_43
{
strings:
	$a0 = { 33c0fa8ed88ed0b8007c8be0fba14e00a30a7ca14c00a3087ca1130448a3130425ff03 }


condition:
	$a0
}