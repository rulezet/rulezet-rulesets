rule Win_Trojan_Natas_9
{
strings:
	$a0 = { 31ff09dd81f7d919c7c6437587e94bf9f583defe87cd31bcbba021db9175ed }


condition:
	$a0
}