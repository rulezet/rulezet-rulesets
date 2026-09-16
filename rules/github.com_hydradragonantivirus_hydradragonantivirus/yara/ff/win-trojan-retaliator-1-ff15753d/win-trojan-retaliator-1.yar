rule Win_Trojan_Retaliator_1
{
strings:
	$a0 = { 0e1f0e07e88600e8fa04b419cd213c027527e84e017405e8c5017403e92802e896027212ba9805e80505e84203 }


condition:
	$a0
}