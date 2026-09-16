rule Win_Trojan_Vienna_110
{
strings:
	$a0 = { 40b9d7008bd681eac300cd2190b43ecd218bd683c23190 }


condition:
	$a0
}