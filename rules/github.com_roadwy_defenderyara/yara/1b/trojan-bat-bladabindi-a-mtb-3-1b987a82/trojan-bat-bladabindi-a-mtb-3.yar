rule Trojan_BAT_Bladabindi_A_MTB_3{
	meta:
		description = "Trojan:BAT/Bladabindi.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {e0 a4 96 e0 a4 a6 e0 a4 9a e0 a4 8b e0 a4 94 e0 a4 8f e0 a4 8f e0 a4 aa e0 a4 9a e0 a4 b7 e0 a4 a6 e0 a4 8f e0 a4 96 e0 a4 98 e0 a4 87 e0 a4 8f e0 a4 af e0 a4 a1 e0 a4 87 e0 a4 a8 e0 a4 aa e0 a4 ac e0 a4 ae e0 a4 9f e0 a4 b7 e0 a4 ad e0 a4 97 e0 a4 a3 e0 a4 a8 e0 a4 af 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}