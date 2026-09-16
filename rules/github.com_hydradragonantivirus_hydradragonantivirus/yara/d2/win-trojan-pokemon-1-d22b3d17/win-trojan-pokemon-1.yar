rule Win_Trojan_Pokemon_1
{
strings:
	$a0 = { 64656275673c633a5c77696e646f77735c706f6b656d6f6e2e646c6c3e6e756c[0-68]5c706f6b656d6f6e2e726567 }


condition:
	$a0
}