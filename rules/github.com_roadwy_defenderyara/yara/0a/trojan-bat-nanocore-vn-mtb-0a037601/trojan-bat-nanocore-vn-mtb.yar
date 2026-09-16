rule Trojan_BAT_NanoCore_VN_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 16 1f ?? 9c 06 17 1f ?? 9c 06 28 ?? ?? ?? 0a 0b 38 ?? ?? ?? 00 07 2a 90 09 06 00 00 28 ?? ?? ?? 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}