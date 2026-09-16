rule Trojan_Win32_Lazy_GMF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 37 59 33 d2 8b c3 f7 f1 80 c2 34 30 54 1c 19 43 83 fb 0e } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}