rule Trojan_BAT_LummaStealer_NM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 7e 00 00 01 13 14 11 09 28 ?? 07 00 0a 16 11 14 16 1a 28 ?? 07 00 0a 11 0a 28 ?? 07 00 0a 16 11 14 } 		$a_01_1 = {46 65 72 6e 61 6e 64 6f 4b 61 70 5f 64 69 67 69 74 61 6c 45 55 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}