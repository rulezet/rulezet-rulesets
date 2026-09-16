rule Win_Trojan_Camel_2
{
strings:
	$a0 = { 86a602a501b8024233c999cd21b440b9a5018d960301cd21b800573e8b96d6023e8b8ed40205 }


condition:
	$a0
}