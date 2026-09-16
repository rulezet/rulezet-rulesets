rule Win_Trojan_Olivia_1
{
strings:
	$a0 = { 022e80343046e2f9bbdcca03d4bbd5cbfd31fc8832ce8e717e8f657efd1f8831ca8a7569fd2688360303ebfd11b0cb35 }


condition:
	$a0
}