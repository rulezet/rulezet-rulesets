rule Trojan_Win32_Copak_GI_MTB{
	meta:
		description = "Trojan:Win32/Copak.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 10 49 81 c0 04 00 00 00 81 ee ?? ?? ?? ?? 39 d8 75 e8 81 c7 ?? ?? ?? ?? c3 89 f6 bf } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}