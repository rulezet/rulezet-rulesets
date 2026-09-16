rule Win_Trojan_Genesis_6
{
strings:
	$a0 = { 130a008d964705e8f60080be130a03730ab43b8d964d05cd2173e88db6d209c6045c }


condition:
	$a0
}