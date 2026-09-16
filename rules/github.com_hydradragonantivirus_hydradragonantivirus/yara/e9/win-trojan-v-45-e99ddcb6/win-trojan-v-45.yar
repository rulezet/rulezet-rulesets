rule Win_Trojan_V_45
{
strings:
	$a0 = { b903008d967402cd21b8024231c931d2cd21b4408d960001b98701cd21b801578a8e7002 }


condition:
	$a0
}