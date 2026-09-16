rule Win_Trojan_Sdbot_3
{
strings:
	$a0 = { d8d19f2a7282d2a3b88ec617e321ec0b5f80605b5ff9f625c36e02c4fc800c8a654165fbc199fd6f56c828a4251bad848286fcf9e94fd0e41c14bf957ae31673 }


condition:
	$a0
}