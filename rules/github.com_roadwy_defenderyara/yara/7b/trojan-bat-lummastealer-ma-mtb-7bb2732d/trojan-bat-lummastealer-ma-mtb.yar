rule Trojan_BAT_LummaStealer_MA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 03 16 11 03 8e 69 28 ?? ?? ?? 06 13 06 20 0c 00 00 00 28 ?? ?? ?? 06 3a 35 fe ff ff 26 38 2b fe ff ff 02 1f 30 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}