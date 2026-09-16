rule Trojan_Win32_Tofsee_BAD_MTB_2{
	meta:
		description = "Trojan:Win32/Tofsee.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d7 29 d2 4a 21 fa 89 3b f8 83 db ?? f8 83 d6 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}