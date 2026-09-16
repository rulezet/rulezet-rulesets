rule Trojan_Win64_Midie_GNS_MTB_2{
	meta:
		description = "Trojan:Win64/Midie.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {2f ef 00 72 ?? 0a d7 30 76 ?? a4 e2 ?? 30 76 ?? dc 72 ?? 30 76 ?? ac 0a 0f 30 76 ?? bc } 		$a_01_1 = {62 61 45 38 2e 4e 55 36 4c } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}