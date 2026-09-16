rule PWS_Win32_Fareit_SM_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 19 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 } 		$a_00_1 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 50 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc } 		$a_00_2 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 3e 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc } 		$a_02_3 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 [0-04] 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*1) >=2
 
}