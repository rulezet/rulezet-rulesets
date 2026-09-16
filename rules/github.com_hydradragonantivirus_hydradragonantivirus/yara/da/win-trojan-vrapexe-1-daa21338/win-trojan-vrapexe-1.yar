rule Win_Trojan_VrapExe_1
{
strings:
	$a0 = { c706910e52468bfcc6055585c5803d55740dbc910e85c5e8f20385c5e90f02e8ea0385c5a1 }


condition:
	$a0
}