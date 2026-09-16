rule Win_Trojan_TVED_1
{
strings:
	$a0 = { 648d318c8d8d74378c8d308e8f66cb8ed9df3ab20d4cb8bd4743af0556d7d13ace05590f4f8c8d43af3ab043af3a }


condition:
	$a0
}