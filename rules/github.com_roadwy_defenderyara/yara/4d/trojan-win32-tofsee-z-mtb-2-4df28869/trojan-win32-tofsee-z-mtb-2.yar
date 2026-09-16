rule Trojan_Win32_Tofsee_Z_MTB_2{
	meta:
		description = "Trojan:Win32/Tofsee.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 57 8b 7d 10 b1 01 85 ff 74 1d 56 8b 75 0c 2b f0 8a 14 06 32 55 14 88 10 8a d1 02 55 18 f6 d9 00 55 14 40 4f 75 ea 5e 8b 45 08 5f 5d c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}