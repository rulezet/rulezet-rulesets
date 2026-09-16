rule Win_Trojan_Trivial_377
{
strings:
	$a0 = { 4eba2301bf2901cd21938b0547478b154747b15a9c81ff350174e99d73e9b44cebe52a2e636f6d00023d9e00004000 }


condition:
	$a0
}