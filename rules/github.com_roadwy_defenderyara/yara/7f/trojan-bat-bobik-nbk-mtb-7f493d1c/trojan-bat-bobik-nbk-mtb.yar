rule Trojan_BAT_Bobik_NBK_MTB{
	meta:
		description = "Trojan:BAT/Bobik.NBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 e8 01 00 0a 58 28 ?? ?? 00 0a 61 69 61 69 fe ?? ?? 00 61 5e } 		$a_01_1 = {4e 20 53 70 6f 6f 66 65 72 } 		$a_01_2 = {4e 65 6f 78 20 53 70 6f 6f 66 65 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}