rule Trojan_Win32_Dridex_AK_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 8d 34 3a 03 c6 8b d6 8d 04 45 90 ca ff ff 0f b7 c0 89 44 24 0c 8a 4c 24 0c 2a ca 8b 54 24 10 83 44 24 10 04 80 e9 02 8b 02 05 3c 17 0d 01 89 02 66 8b 54 24 0c } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}