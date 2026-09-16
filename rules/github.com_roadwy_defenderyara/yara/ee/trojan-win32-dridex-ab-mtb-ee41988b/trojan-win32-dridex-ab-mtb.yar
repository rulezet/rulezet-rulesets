rule Trojan_Win32_Dridex_AB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 8d b4 e6 ff ff 8b 45 0c 0f b6 00 83 f8 31 ?? ?? 83 f8 35 ?? ?? 33 8d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}