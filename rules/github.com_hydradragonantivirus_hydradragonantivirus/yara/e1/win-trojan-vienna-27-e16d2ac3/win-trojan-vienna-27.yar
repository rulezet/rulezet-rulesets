rule Win_Trojan_Vienna_27
{
strings:
	$a0 = { efdb018bf7b9a001ac32c3aa4975f95a595b58c3e8dfffb4408bfa2bd1b9f401cd218bd7e8cfff }


condition:
	$a0
}