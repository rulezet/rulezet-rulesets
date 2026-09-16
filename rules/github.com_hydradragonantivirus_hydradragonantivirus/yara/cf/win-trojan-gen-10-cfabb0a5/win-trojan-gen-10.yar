rule Win_Trojan_Gen_10
{
strings:
	$a0 = { 1e6803a3e6005be84300b440b9a300ba6a03cd21e82d00b440b92500ba4503cd215a59b80157cd }


condition:
	$a0
}