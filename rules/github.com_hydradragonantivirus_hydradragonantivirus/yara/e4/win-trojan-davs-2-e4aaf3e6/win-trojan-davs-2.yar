rule Win_Trojan_Davs_2
{
strings:
	$a0 = { bf9080400083c9fff2aef7d12bf98bf78be98bfa83c9fff2ae8bcd4fc1e902f3a58bcd8d84241801000083e10350f3a48d4c241851ff15607040008be883fdff0f8479010000 }


condition:
	$a0
}