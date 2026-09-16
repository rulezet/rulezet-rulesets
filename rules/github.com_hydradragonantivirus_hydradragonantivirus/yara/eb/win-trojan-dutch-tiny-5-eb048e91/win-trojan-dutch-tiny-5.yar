rule Win_Trojan_Dutch_Tiny_5
{
strings:
	$a0 = { e973014e89f7ad31d8abe2fa5e595b58c3e8dcff89843e02b4408d940501b93601cd219c }


condition:
	$a0
}