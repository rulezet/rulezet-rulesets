rule Trojan_BAT_LummaStealer_MB_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 17 1f 0b 6f ?? ?? ?? 0a 0c 08 02 8e 69 3c ?? ?? ?? ?? 08 02 8e 69 3d ?? ?? ?? ?? 73 ?? ?? ?? 06 26 2a } 		$a_01_1 = {64 31 37 62 34 31 63 39 2d 33 39 35 35 2d 34 38 39 30 2d 39 35 62 38 2d 38 38 37 61 61 63 30 30 36 65 30 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}