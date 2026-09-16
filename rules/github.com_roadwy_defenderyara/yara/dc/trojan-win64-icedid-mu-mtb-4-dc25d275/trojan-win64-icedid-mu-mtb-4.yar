rule Trojan_Win64_IcedID_MU_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 63 5e 75 5e 72 5e 6c 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-10] 2e 6d 73 69 20 68 74 74 70 3a 2f 2f [0-15] 2f [0-10] 2f [0-10] 26 26 74 69 6d 65 6f 75 74 20 31 35 26 26 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-10] 2e 6d 73 69 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}