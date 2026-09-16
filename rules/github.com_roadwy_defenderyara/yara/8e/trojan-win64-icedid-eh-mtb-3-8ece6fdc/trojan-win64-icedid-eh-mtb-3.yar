rule Trojan_Win64_IcedID_EH_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 40 48 03 c8 [0-03] 74 } 		$a_01_1 = {8a 40 01 66 3b ed 74 00 88 44 24 21 8a 4c 24 20 e9 bf fc ff ff 88 44 24 20 48 8b 44 24 38 66 3b db 74 40 41 83 c0 0e } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*4) >=7
 
}