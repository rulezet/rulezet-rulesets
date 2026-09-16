rule Trojan_BAT_LummaStealer_NA_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 61 38 00 06 0c 28 ?? ?? 00 0a 03 6f ?? ?? 00 0a 28 ?? ?? 00 06 0d 73 ?? ?? 00 0a 13 04 28 ?? ?? 00 06 13 05 11 05 08 6f ?? ?? 00 0a 11 05 09 6f ?? ?? 00 0a 11 04 11 05 } 		$a_01_1 = {6c 69 76 65 5f 73 74 72 65 61 6d 5f 66 72 6f 6d 5f 63 6f 73 6d 6f 73 5f 65 76 65 6e 74 73 5f 61 70 70 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}