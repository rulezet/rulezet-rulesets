rule Win_Trojan_Trojan_194
{
strings:
	$a0 = { bf1e0db9ae013bfc7204b44ccd21fdf3a5fc8bf7bf0001adad8be8b210e9b00b646c7a0099027a6a005d05ff1f }


condition:
	$a0
}