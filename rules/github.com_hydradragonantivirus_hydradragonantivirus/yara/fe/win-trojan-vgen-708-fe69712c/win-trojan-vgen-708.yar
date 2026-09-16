rule Win_Trojan_VGEN_708
{
strings:
	$a0 = { cef99045cef99045cef99045cef99045cef99045cef99045cef99045cef99045ceb9c807cef99045cef99045ce }


condition:
	$a0
}