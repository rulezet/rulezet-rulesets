rule Win_Trojan_Agent_34754
{
strings:
	$a0 = { ba947e4000e865a1ffffa190f54000bab07e4000e892a2ffff750d8d45f4babc7e4000e847a1ffff }


condition:
	$a0
}