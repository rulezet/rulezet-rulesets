rule Trojan_Win32_Gatak_DT_dha_3{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 4d 44 20 2f 43 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 53 59 53 54 45 4d 49 4e 46 4f 20 26 26 20 44 45 4c } 	condition:
		((#a_01_0  & 1)*5) >=100
 
}