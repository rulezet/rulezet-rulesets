rule Win_Trojan_C_27
{
strings:
	$a0 = { 5d81ed13008bf581c60e008a148a64018bf581c637008bfeb93f0390ac2ac402e2aae2f8 }


condition:
	$a0
}