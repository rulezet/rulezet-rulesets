rule Win_Trojan_Vgen_146
{
strings:
	$a0 = { ed16ed16ed16ed16ed16ed16ed16ed16be000156b9e603c70482c0c64402fb813436cd4646e2f831f631c9c300 }


condition:
	$a0
}