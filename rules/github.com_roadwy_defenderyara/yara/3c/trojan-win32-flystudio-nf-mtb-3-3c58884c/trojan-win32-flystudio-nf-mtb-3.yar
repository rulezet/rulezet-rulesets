rule Trojan_Win32_Flystudio_NF_MTB_3{
	meta:
		description = "Trojan:Win32/Flystudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {3b f0 73 1e 80 66 04 00 83 0e ?? 83 66 08 00 c6 46 05 ?? a1 60 bc 61 00 83 c6 ?? 05 80 04 00 00 eb de } 		$a_03_1 = {eb de 8d 45 ?? 50 ff 15 94 51 49 00 66 83 7d ?? 00 0f 84 d1 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}