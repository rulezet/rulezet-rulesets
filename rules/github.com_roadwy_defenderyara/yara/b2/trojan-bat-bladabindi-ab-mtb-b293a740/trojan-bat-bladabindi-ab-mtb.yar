rule Trojan_BAT_Bladabindi_AB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 e3 00 00 70 72 bf 00 00 70 6f ?? ?? ?? 0a 00 73 4a 00 00 0a 0d 09 6f ?? ?? ?? 0a 72 bf 00 00 70 6f ?? ?? ?? 0a 00 09 6f } 		$a_01_1 = {7a 00 69 00 72 00 6f 00 6c 00 61 00 6e 00 64 00 20 00 67 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}