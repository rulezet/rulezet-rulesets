rule Win_Trojan_Dima_2
{
strings:
	$a0 = { 062e8b36010181c603015683ee0ebf0001b90700f3a45eb800008ed8803e1204447478b44abbffffcd218bee45 }


condition:
	$a0
}