rule Win_Trojan_Mik_1
{
strings:
	$a0 = { 027b750a803e7f7d007552e98400c60600027b8b1613044a89161304b106d3e28ec2be007c }


condition:
	$a0
}