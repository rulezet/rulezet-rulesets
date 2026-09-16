rule Win_Trojan_Peed_226
{
strings:
	$a0 = { b807d734020f820e0000006833dd530059bb2d921801f7d94b }


condition:
	$a0
}