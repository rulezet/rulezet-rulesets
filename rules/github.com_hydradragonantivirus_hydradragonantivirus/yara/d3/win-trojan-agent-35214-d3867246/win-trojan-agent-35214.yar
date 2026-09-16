rule Win_Trojan_Agent_35214
{
strings:
	$a0 = { cda72f2470fb351eec71874fad543b3925c731800f6606e9e4066da3ca29cb415883a60680166fef4cec13925b2a60f77bc527a76bfcec7ea450a9737ed435f31e9e6e60e8a5c41db9fffeee0924 }


condition:
	$a0
}