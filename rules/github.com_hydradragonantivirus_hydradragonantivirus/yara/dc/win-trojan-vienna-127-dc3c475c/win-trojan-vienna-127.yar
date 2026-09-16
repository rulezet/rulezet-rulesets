rule Win_Trojan_Vienna_127
{
strings:
	$a0 = { 5051e80100905b83eb18fcbf00018d37b90300f3a48bf3558bec83ec7cb430cd21 }


condition:
	$a0
}