rule Trojan_Win64_Convagent_MX_MTB_2{
	meta:
		description = "Trojan:Win64/Convagent.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 1e 45 33 c0 48 8d 95 c0 03 00 00 48 8d 4d a0 ff 15 3d 23 00 00 48 8d 4d a0 ff 15 1b 23 00 00 0f 57 c0 } 		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 31 33 33 37 5c 53 6f 75 72 63 65 5c 52 65 70 6f 73 5c 73 70 72 65 61 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6c 6f 61 64 65 72 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}