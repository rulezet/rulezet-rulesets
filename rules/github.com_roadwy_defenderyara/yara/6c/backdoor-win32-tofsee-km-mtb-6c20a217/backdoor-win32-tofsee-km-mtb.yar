rule Backdoor_Win32_Tofsee_KM_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 c0 7b 89 45 fc b8 f9 cd 03 00 01 45 fc 83 6d fc 7b 8b 45 fc 8a 04 08 88 04 0a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}