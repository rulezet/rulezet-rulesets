rule Backdoor_Win32_Lotok_GNA_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f7 31 db b9 ?? ?? ?? ?? ac 49 32 06 88 07 60 fd 89 d3 50 59 fc 61 83 c6 ?? 83 c7 ?? 49 85 c9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}