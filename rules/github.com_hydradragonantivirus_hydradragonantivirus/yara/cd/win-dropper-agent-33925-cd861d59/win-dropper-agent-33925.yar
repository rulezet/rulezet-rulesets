rule Win_Dropper_Agent_33925
{
strings:
	$a0 = { 89e5[0-6]81ec????000056 }

	$a1 = { c745 }

	$a2 = { 8175[5-11]c745[5-11]8175[5-11]c745[5-11]8175[5-11]c745[5-11]8175 }


condition:
	$a0 and $a1 and $a2
}