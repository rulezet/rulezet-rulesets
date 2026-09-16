rule Trojan_Win64_LummaStealer_BSA_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 e8 9f f6 ?? ?? e8 a6 b9 ff ff 8b c8 48 83 c4 28 } 		$a_03_1 = {48 8d 0d 51 42 03 00 e8 08 8d 00 00 85 c0 74 0a [0-16] 00 48 8d 0d 88 41 03 00 e8 a3 8c 00 } 	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*3) >=11
 
}