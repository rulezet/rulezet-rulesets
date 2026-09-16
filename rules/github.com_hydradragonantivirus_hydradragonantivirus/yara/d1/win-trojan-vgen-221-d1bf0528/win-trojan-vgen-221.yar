rule Win_Trojan_VGEN_221
{
strings:
	$a0 = { ed07013efe8edc01bf0001578db6d201a5a5501f1e5b3bc374082ec6060001c358c30e1fb41aba00fecd21b44e }


condition:
	$a0
}