rule Trojan_Win32_LummaStealer_BSA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 65 71 75 61 6c 2e 65 78 65 } 		$a_03_1 = {eb 10 66 62 3a 43 2b ?? ?? ?? ?? ?? ?? e9 ac b0 73 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*3) >=13
 
}