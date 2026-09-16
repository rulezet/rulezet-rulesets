rule Trojan_BAT_LummaStealer_A_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 17 58 17 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? ?? 03 08 19 58 18 59 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 19 58 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 1a 58 19 59 6e 5a 31 b1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}