rule Trojan_Win64_LoudEarplugs_B_dha{
	meta:
		description = "Trojan:Win64/LoudEarplugs.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bc b4 e7 b1 e6 b7 b4 e7 bd b1 b4 b7 b3 b2 e0 e4 b6 e0 bc e7 e4 e7 bc b7 b6 bc b3 b6 b4 bd e0 b2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}