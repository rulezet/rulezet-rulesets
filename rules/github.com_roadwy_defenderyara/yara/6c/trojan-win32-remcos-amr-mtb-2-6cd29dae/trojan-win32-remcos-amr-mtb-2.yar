rule Trojan_Win32_Remcos_AMR_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 68 04 01 00 00 ff 15 ?? ?? ?? ?? 68 60 32 27 09 8d 85 e4 f9 ff ff 50 ff 15 ?? ?? ?? ?? c7 85 d8 f7 ff ff b0 32 27 09 c7 85 d0 f7 ff ff dc 32 27 09 c7 85 d4 f7 ff ff f0 32 27 09 68 04 01 00 00 8d 8d dc f7 ff ff 51 6a 00 ff 15 ?? ?? ?? ?? 8b 95 cc f7 ff ff 52 8d 85 f4 fd ff ff 50 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}