rule Trojan_BAT_Formbook_AZ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 18 09 11 17 07 11 17 91 11 04 11 18 95 61 28 ?? 00 00 0a 9c 00 11 17 17 58 13 17 11 17 09 8e 69 fe 04 } 		$a_01_1 = {34 00 38 00 46 00 57 00 37 00 43 00 34 00 38 00 45 00 46 00 42 00 48 00 35 00 38 00 43 00 39 00 5a 00 46 00 35 00 37 00 31 00 34 00 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}