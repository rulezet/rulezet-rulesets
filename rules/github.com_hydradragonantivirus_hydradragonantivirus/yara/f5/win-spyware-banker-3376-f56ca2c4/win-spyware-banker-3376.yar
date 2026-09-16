rule Win_Spyware_Banker_3376
{
strings:
	$a0 = { ebcb81965c4132ad534fa4d8d4c782910b71f9a00633d48348f874386ae4f4b5a061584d797331bbd506d8429813b4cea1cd4c217890ce7e1c8dcb4bfc0704dbb01bcf018d5c }


condition:
	$a0
}