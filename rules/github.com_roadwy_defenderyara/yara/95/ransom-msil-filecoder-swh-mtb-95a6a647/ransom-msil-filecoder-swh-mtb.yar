rule Ransom_MSIL_Filecoder_SWH_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 53 79 73 74 65 6d } 		$a_01_1 = {24 62 38 34 31 63 32 39 61 2d 66 32 64 33 2d 34 61 30 38 2d 62 62 38 30 2d 34 34 33 31 35 36 31 36 64 31 63 37 } 		$a_01_2 = {45 6e 74 65 72 6e 61 6c 52 65 64 5c 6f 62 6a 5c 44 65 62 75 67 5c 4a 50 47 2d 44 61 74 65 69 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}