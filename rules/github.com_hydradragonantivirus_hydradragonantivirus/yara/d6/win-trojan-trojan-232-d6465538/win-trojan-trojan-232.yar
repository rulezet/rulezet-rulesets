rule Win_Trojan_Trojan_232
{
strings:
	$a0 = { 963000b9f3018db656008bfead33c2abe2fab930008db666048bfead33c2abe2fac3 }


condition:
	$a0
}