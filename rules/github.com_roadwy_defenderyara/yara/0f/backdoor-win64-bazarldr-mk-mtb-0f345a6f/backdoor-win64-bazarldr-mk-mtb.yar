rule Backdoor_Win64_Bazarldr_MK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af d0 89 d0 44 31 f8 25 [0-04] bd [0-04] 21 ea 09 c2 89 d0 31 e8 83 e0 fe 81 f2 [0-04] 09 c2 44 39 fa 0f 94 c0 0f 95 c2 83 f9 [0-01] 0f 9c c3 83 f9 [0-01] 0f 9f c1 20 c8 08 d1 20 d3 08 c3 89 c8 30 d8 b8 [0-04] ba [0-04] 0f 45 c2 84 db 89 c5 ba [0-04] 0f 45 ea 48 89 74 24 70 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}