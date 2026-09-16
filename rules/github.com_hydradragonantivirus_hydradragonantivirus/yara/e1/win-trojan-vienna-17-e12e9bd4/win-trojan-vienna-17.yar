rule Win_Trojan_Vienna_17
{
strings:
	$a0 = { 030103c18905b4408bfa2bd1b95501cd217303eb1e903d55017518b80042b900008bd1cd21 }


condition:
	$a0
}