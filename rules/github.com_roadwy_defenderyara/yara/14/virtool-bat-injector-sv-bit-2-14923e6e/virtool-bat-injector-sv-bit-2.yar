rule VirTool_BAT_Injector_SV_bit_2{
	meta:
		description = "VirTool:BAT/Injector.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 53 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_1 = {46 00 4c 00 69 00 62 00 2e 00 46 00 4c 00 69 00 62 00 } 		$a_03_2 = {06 08 06 8e b7 5d 91 61 02 08 17 d6 02 8e b7 5d 91 da 20 ?? ?? ?? ?? d6 20 ?? ?? ?? ?? 5d b4 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}