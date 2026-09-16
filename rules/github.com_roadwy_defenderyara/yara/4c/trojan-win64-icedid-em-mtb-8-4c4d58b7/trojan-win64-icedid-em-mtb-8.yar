rule Trojan_Win64_IcedID_EM_MTB_8{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 3b ed 74 1d b8 6c 00 00 00 66 89 44 24 64 66 3b d2 74 dc 48 89 54 24 10 48 89 4c 24 08 3a ff 74 dc 48 81 ec f8 00 00 00 48 c7 44 24 50 00 00 00 00 3a d2 74 1c b8 6c 00 00 00 66 89 44 24 62 3a ed 74 c1 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}