rule Trojan_BAT_LummaStealer_GPB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 81 1c 00 00 01 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 3f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}