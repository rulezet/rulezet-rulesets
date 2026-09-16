rule Win_Trojan_Hupigon_33
{
strings:
	$a0 = { 558bec6a006a00689022141368b42214136a00e8a8ffffff6a056808231413e8d4feffff33c05dc20400 }


condition:
	$a0
}