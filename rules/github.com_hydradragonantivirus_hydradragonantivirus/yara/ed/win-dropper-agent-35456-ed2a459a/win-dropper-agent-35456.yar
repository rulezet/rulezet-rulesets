rule Win_Dropper_Agent_35456
{
strings:
	$a0 = { 558bec83ec185657e8d4f1ffff84c074 }

	$a1 = { 5c007300610066006500620072006500610073 }

	$a2 = { 48414c2e646c6c }


condition:
	$a0 and $a1 and $a2
}