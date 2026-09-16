rule Trojan_BAT_NanoCore_VN_MTB_6{
	meta:
		description = "Trojan:BAT/NanoCore.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 72 b9 00 00 70 28 ?? ?? ?? 06 0c 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 0d 09 16 14 a2 00 09 17 14 a2 00 09 14 14 14 17 28 ?? ?? ?? 0a 26 00 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}