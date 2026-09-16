rule Trojan_Win32_Flystudio_NF_MTB_2{
	meta:
		description = "Trojan:Win32/Flystudio.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb de 8d 45 ?? 50 ff 15 9c 21 47 00 66 83 7d ea 00 0f 84 d1 } 		$a_03_1 = {83 f9 ff 74 38 8a 03 a8 01 74 32 a8 ?? 75 0b 51 ff 15 50 23 47 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}