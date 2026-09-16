rule Ransom_Win32_Sarento_C_3{
	meta:
		description = "Ransom:Win32/Sarento.C,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {76 69 63 74 3f 63 75 73 74 3d } 	condition:
		((#a_01_0  & 1)*1) >=100
 
}