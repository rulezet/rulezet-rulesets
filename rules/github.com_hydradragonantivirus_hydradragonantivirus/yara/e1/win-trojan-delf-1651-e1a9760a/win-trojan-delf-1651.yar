rule Win_Trojan_Delf_1651
{
strings:
	$a0 = { ba24280610e8941efaff6a008b45f8e8b220faff508d45f8e80123faff8bd08d85a4fdffff59e88707faffe8fa00faff8d85a4fdffffe89707faffe8ea00faff6a006a006a0068382806106a006a00e86249faff }


condition:
	$a0
}