rule Win_Trojan_Crypted_25
{
strings:
	$a0 = { 83ec04892c248bec8bffeb013683ec1c87c9525ae83afdffff9050908bc00508114000eb016f83e80d87c9ffd058eb0133eb0116c745ec0d40000068 }


condition:
	$a0
}