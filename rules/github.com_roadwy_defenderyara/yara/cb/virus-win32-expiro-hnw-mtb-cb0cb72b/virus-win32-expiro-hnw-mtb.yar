rule Virus_Win32_Expiro_HNW_MTB{
	meta:
		description = "Virus:Win32/Expiro.HNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e 73 79 6d 74 61 62 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e2 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}