rule Win_Trojan_JAVA_1
{
strings:
	$a0 = { 2ab300ee2ab400d9c700222abb0083592ab70104b500d92ab400d904b601 }


condition:
	$a0
}