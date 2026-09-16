rule Acecard
{
	meta:
		description = "Detects some acecard samples"
		author = "vitorafonso"
		sample = "0973da0f5cc7e4570659174612a650f3dbd93b3545f07bcc8b438af09dc257a9"
		report = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"

	strings:
		$a = "#control_number"
		$b = "client number"
		$c = "INTERCEPTING_INCOMING_ENABLED"
		$d = "#intercept_sms_start"
		$e = "#intercept_sms_stop"
		$f = "intercepted incoming sms"

	condition:
		all of them
}