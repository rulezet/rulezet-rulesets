rule Win_Trojan_Pingwin_1
{
strings:
	$a0 = { 23e627bf23dede9831210aeb9561aa3f3122ec00c975df9123aa3f3122c97721982123d6d02af355 }


condition:
	$a0
}