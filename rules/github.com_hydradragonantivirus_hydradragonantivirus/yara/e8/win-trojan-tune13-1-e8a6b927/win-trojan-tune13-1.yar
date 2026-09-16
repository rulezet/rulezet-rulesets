rule Win_Trojan_Tune13_1
{
strings:
	$a0 = { b41acd21e84401b82435cd2153060e07b82425ba0c02cd212ea140032ea34203b42acd2180fa0d7503e8e100ba }


condition:
	$a0
}