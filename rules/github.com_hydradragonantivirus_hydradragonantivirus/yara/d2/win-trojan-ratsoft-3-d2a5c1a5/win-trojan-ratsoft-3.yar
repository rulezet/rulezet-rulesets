rule Win_Trojan_RatSoft_3
{
strings:
	$a0 = { 01b900008b164b018b1e4d01b80042cd217239ba1001b93c038b1e4d01b440cd217229b900 }


condition:
	$a0
}