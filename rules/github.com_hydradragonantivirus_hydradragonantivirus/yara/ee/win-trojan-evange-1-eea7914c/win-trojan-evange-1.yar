rule Win_Trojan_Evange_1
{
strings:
	$a0 = { 6966202531403d3d6576616e67656c696a614020676f746f207265706f7274 }


condition:
	$a0
}