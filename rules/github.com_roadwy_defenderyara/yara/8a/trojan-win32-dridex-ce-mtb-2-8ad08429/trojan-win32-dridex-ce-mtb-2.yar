rule Trojan_Win32_Dridex_CE_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.CE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 c0 02 83 e8 02 83 e8 02 cc 83 c0 02 83 e8 02 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}