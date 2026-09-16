rule Win_Trojan_SillyC_199
{
strings:
	$a0 = { 0353bea7018b4006a300018a4008a20201b41a8bd303d683c211cd211ea12c008ed8ba0800b44eb90000cd2173 }


condition:
	$a0
}