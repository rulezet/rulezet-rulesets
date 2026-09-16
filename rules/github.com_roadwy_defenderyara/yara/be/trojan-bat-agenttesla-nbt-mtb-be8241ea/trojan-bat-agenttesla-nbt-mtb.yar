rule Trojan_BAT_AgentTesla_NBT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 16 00 fe ?? ?? 00 58 4a 97 29 ?? ?? ?? 11 a2 fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 9c fe ?? ?? 00 20 ?? ?? ?? 00 } 		$a_01_1 = {41 6e 74 69 41 6e 61 6c 79 73 69 73 } 		$a_01_2 = {6e 6f 6e 53 65 63 72 65 74 50 61 79 6c 6f 61 64 4c 65 6e 67 74 68 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}