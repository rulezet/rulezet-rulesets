rule Trojan_BAT_Redcap_NRC_MTB{
	meta:
		description = "Trojan:BAT/Redcap.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 be 00 00 0a 16 13 18 dd ?? ?? 00 00 11 13 7b ?? ?? 00 04 11 0b 6f ?? ?? 00 0a 26 14 13 0c 72 ?? ?? 00 70 73 ?? ?? 00 0a 13 0d 11 07 13 0e } 		$a_01_1 = {46 69 72 65 66 6f 78 50 61 73 73 77 6f 72 64 47 72 61 62 62 65 72 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}