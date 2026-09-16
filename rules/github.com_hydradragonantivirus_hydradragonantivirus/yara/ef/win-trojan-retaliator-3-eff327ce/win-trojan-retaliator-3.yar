rule Win_Trojan_Retaliator_3
{
strings:
	$a0 = { 0e1f0e07e88600e81405b419cd213c027527e84e017405e8d9017403e93c02e8aa027212bab205e81f05e85603 }


condition:
	$a0
}