rule Win_Trojan_Q_1
{
strings:
	$a0 = { c42e2a00fe4602b449cd21bf7d034db452cd21fc26c577220e078bc7a5a58c4cfe8944fcb8 }


condition:
	$a0
}