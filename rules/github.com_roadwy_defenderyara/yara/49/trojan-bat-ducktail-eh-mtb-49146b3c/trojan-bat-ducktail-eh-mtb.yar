rule Trojan_BAT_DUCKTAIL_EH_MTB{
	meta:
		description = "Trojan:BAT/DUCKTAIL.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {e9 82 3c ff e5 65 0e ff e5 65 0e ff e5 65 0e ff e5 65 0e ff e5 65 0e ff e5 65 0d ff e8 6f 1d ff fd ba 8a ff ff c2 95 ff e5 65 0e } 		$a_01_1 = {e2 d0 2e 73 b1 f1 13 86 61 82 99 c2 c2 42 3c d0 ac 3f b4 e8 64 9b 04 f0 42 1c 3e 18 b0 d0 f8 09 c3 30 c1 4c ee d9 0b b8 bf 29 05 c0 30 9e 0c 05 } 		$a_01_2 = {12 12 d6 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 02 02 d3 ff 22 22 d9 ff } 		$a_01_3 = {ee 0b 02 ba 4b b8 56 45 30 c8 12 20 01 54 c8 13 58 90 07 2b 72 ac 20 ee 2a 82 11 24 1c a2 b0 10 10 64 63 60 51 21 18 c2 25 90 10 89 86 74 f5 31 } 		$a_01_4 = {68 69 6a 61 63 6b 4c 6f 63 6b 48 6f 6c 64 65 72 2e 41 63 71 75 69 72 65 64 2e } 		$a_01_5 = {43 6f 72 65 68 6f 73 74 2e 53 74 61 74 69 63 5c 73 69 6e 67 6c 65 66 69 6c 65 68 6f 73 74 2e 70 64 62 } 		$a_01_6 = {43 72 65 61 74 65 4d 65 6d 6f 72 79 52 65 73 6f 75 72 63 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}