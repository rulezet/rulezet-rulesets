rule Trojan_Win64_MeduzaStealer_BSA_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 53 48 83 ec 60 48 8b 05 b3 6c 37 00 48 33 c4 48 89 44 24 50 33 c0 33 c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}