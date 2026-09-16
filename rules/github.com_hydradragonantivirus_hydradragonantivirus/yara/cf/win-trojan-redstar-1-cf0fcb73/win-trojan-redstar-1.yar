rule Win_Trojan_Redstar_1
{
strings:
	$a0 = { 080080fc6c2eff2e9400505351521eb8023d9c80fc6c2e }


condition:
	$a0
}