rule Win_Trojan_Bancos_1764
{
strings:
	$a0 = { adac2ce8b720018af31da0cc0963ffb5ffe20e8f838b12320daf4a9dc185af7dc20f4ecb6a5c6abc2f36efeba7e214ef3a2bb7e36df7df75b8b99aef407caaa65266cf135b48 }


condition:
	$a0
}