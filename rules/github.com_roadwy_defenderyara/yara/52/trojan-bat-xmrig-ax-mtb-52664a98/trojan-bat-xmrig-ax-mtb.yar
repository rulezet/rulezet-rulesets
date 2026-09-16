rule Trojan_BAT_Xmrig_AX_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 14 0b 14 0c 14 0d 28 ?? ?? ?? 0a 1a 33 0e 72 32 0f 00 70 0c 72 7c 0f 00 70 0d 2b 0c 72 98 0f 00 70 0c 72 e2 0f 00 70 0d 06 08 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}