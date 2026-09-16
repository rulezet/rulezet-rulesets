rule Trojan_BAT_Clipbanker_NCB_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 72 bd 07 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 06 6f ?? ?? 00 0a 25 07 6f ?? ?? 00 06 } 		$a_01_1 = {52 00 6f 00 6f 00 62 00 65 00 74 00 43 00 72 00 61 00 73 00 68 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}