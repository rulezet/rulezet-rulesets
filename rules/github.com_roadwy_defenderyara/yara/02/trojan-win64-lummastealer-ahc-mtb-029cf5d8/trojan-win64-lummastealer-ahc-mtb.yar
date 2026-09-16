rule Trojan_Win64_LummaStealer_AHC_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 87 db 48 8d 1b 90 4d 8d 12 90 4d 87 d2 90 e9 } 		$a_01_1 = {41 5a 48 89 c9 4d 89 c0 4d 89 c9 41 51 4d 87 c9 41 59 } 	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}