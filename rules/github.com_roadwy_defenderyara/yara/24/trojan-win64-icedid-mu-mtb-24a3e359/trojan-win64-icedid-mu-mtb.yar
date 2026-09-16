rule Trojan_Win64_IcedID_MU_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 3e 10 48 ba 61 61 61 61 61 61 61 61 31 c9 49 89 f0 48 89 10 48 89 50 08 48 89 50 10 48 89 50 18 48 89 50 20 48 89 50 28 48 89 50 30 48 89 50 38 49 63 c7 31 d2 c6 44 04 20 00 c6 44 1c 20 00 ff 15 ea 68 08 00 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}