rule VirTool_WinNT_Chksyn_A_2{
	meta:
		description = "VirTool:WinNT/Chksyn.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 17 04 00 00 c2 2c 00 85 c0 74 04 01 07 eb 0e c7 45 d8 0f 00 00 c0 eb db 8b de 89 5d d0 ff 75 e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}