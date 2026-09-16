rule Win_Trojan_Ai22_1
{
strings:
	$a0 = { 7b062e8b9c5e07b440cd21e8affb2e8f8476072e8f846d }


condition:
	$a0
}