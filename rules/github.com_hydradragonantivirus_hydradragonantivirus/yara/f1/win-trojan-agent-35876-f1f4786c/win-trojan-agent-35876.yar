rule Win_Trojan_Agent_35876
{
strings:
	$a0 = { e90bbbffff538d1a81f31a45cb5687d35b81f25218aa0081f25218aa0081f21a45cb56 }


condition:
	$a0
}