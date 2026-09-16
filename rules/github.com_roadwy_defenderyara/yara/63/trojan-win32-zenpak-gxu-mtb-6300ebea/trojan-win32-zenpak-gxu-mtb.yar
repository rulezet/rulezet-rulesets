rule Trojan_Win32_Zenpak_GXU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 89 d0 89 d8 50 8f 05 ?? ?? ?? ?? 29 c2 8d 05 ?? ?? ?? ?? 01 38 31 c2 29 d0 83 e8 ?? 8d 05 ?? ?? ?? ?? 01 28 e8 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}