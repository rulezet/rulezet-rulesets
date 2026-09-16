rule Win_Trojan_Amusak_1
{
strings:
	$a0 = { 0150e8ec08595dc3558bec568b76040bf67c1483fe587603be57008936c2018a84c4019896eb }


condition:
	$a0
}