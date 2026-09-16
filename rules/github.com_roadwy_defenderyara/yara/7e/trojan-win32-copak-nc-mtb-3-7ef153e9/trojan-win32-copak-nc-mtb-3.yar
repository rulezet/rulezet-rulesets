rule Trojan_Win32_Copak_NC_MTB_3{
	meta:
		description = "Trojan:Win32/Copak.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 30 00 00 00 bf ee 4f eb e4 01 fe 31 03 81 ee ?? ?? ?? ?? 81 c6 64 92 78 96 81 c3 ?? ?? ?? ?? 09 fe 39 d3 75 c8 } 		$a_03_1 = {81 c2 01 00 00 00 81 eb ?? ?? ?? ?? 81 ef 40 6c dd 10 81 fa ?? ?? ?? ?? 75 05 ba 00 00 00 00 09 fb 81 eb } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}