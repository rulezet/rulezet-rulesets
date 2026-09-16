rule Win_Trojan_Trojan_133
{
strings:
	$a0 = { 0600004c4d26c7060200415307b41a99ccb44e2bc9baf901cc727eb8023dba1e00cc72d28bd8 }


condition:
	$a0
}