rule Win_Trojan_Hupigon_532
{
strings:
	$a0 = { 37f25fae025a1939ce304d543f0f13736e0e83ffd9e7bd21bbeefc4d97a61e542967bfb8bf6a0f8fcd12cba6b205f0197ab7af61051174220aac7a9e4c23fad89a237b6ea3e2aef9cac83d9873b5 }


condition:
	$a0
}