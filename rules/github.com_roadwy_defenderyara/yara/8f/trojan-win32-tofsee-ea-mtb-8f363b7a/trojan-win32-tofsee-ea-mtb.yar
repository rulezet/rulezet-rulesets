rule Trojan_Win32_Tofsee_EA_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f3 33 f7 29 75 f4 83 6d ec 01 0f 85 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}