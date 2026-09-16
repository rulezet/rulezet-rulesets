rule Win_Trojan_DEV2000_1
{
strings:
	$a0 = { 4b03cd21729f93bdd00733d2e88dfe50b4408bcdcd215893724750b43f8bd7b900a0cd2195 }


condition:
	$a0
}