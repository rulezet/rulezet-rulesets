rule Win_Trojan_SdBot_3647
{
strings:
	$a0 = { aa319117c0b89cfd811c3d70bcf5e8aa4c25986d466a655e824a6dcc116c4aeeabbd3a37a2a590c29d417c3b5a711be0fba8f9b59c673c506bbdd09ee04fc85a80a4af892b1dd2cc50fd83253fd8 }


condition:
	$a0
}