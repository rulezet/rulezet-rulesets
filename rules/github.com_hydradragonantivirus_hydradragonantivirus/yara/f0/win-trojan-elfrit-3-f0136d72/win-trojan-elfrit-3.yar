rule Win_Trojan_Elfrit_3
{
strings:
	$a0 = { ba7c3619ffffcd0964013d7b46393034656c665f436c69656e7400fffffff93031412d41ffcc310006dc06d6f233c38b49884573a0391b6e734dfeffffff7c9224b6 }


condition:
	$a0
}