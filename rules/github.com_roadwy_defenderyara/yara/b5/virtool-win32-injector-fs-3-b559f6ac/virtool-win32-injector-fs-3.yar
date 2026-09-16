rule VirTool_Win32_Injector_FS_3{
	meta:
		description = "VirTool:Win32/Injector.FS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 c4 2f c6 45 c5 63 c6 45 c6 20 c6 45 c7 70 c6 45 c8 69 c6 45 c9 6e c6 45 ca 67 c6 45 cb 20 c6 45 cc 31 c6 45 cd 32 c6 45 ce 37 c6 45 cf 2e [0-80] c6 45 e1 33 c6 45 e2 32 c6 45 e3 2e c6 45 e4 65 c6 45 e5 78 c6 45 e6 65 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}