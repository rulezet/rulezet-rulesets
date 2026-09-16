rule Trojan_Win64_Cobaltstrike_DG_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 03 ?? 48 89 f1 4c 8d 40 01 48 c1 f9 08 31 f2 31 ca 48 89 f1 48 c1 f9 10 31 ca 48 89 f1 48 c1 f9 18 31 ca 48 8d 4e 01 88 54 03 ?? 49 39 f8 0f 8d } 		$a_03_1 = {48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0a 48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0b 48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0c 48 39 ce 7e ?? 30 54 0b ?? 48 8d 48 0d 48 39 ce 7e ?? 30 54 0b ?? 48 83 c0 0e 48 39 c6 7e } 		$a_03_2 = {30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 30 54 0b 10 48 8d 48 ?? 48 39 ce 7e ?? 48 83 c0 06 30 54 0b 10 48 39 c6 7e } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=10
 
}