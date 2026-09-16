rule Win_Trojan_Rajaat_3
{
strings:
	$a0 = { 50cd215152b4408d960401b9c100cd21b442992bc9cd21b4408d96bb01b90400cd215a5958 }


condition:
	$a0
}