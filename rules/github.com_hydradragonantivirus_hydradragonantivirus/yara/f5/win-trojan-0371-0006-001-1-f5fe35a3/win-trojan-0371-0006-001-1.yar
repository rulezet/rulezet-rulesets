rule Win_Trojan__0371_0006_001_1
{
strings:
	$a0 = { cc7210b8004233c999ccb90400ba8200b440ccb801575a59ccb43eccb80143591f5acc5e595b58 }


condition:
	$a0
}