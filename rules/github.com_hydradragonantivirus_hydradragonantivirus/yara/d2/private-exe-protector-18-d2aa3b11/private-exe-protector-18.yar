rule _Private_EXE_Protector_18_
{
	meta:
		description = "Private EXE Protector 1.8"
	strings:
		$0 = {BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0}
	condition:
		$0
}