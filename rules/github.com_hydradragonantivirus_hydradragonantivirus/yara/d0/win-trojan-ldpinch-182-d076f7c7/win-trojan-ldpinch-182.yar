rule Win_Trojan_LdPinch_182
{
strings:
	$a0 = { 0bf66683c20068e3291b64f56685f631f69b9bb9006020015159c1c906909bb8 }


condition:
	$a0
}