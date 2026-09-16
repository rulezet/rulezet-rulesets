rule Win_Trojan_Max_1
{
strings:
	$a0 = { 580241ba8000cd1326803fe87416b8010341cd138d76fd8bfbb95b01f3a4b8010341cd138bf5 }


condition:
	$a0
}