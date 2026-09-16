rule Backdoor_Win32_Farfli_GZZ_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 34 2c 6b 78 48 38 } 		$a_01_1 = {9d 10 fb 22 5a 61 01 29 24 37 4c 10 59 52 3b f0 71 ed } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}