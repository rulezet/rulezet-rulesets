rule Win_Trojan_Agent_35109
{
strings:
	$a0 = { a28e2c3ef0d2346b53c7606e669cfe985bbe46e1480b958ed244960cd07a375c2cc0c28956c667cccc245cff7a24d8cffa8f582a0e2ebece620aa742 }


condition:
	$a0
}