rule Win_Trojan_Delf_1449
{
strings:
	$a0 = { ba70994600e859b3f9ff8b85ecfdffffe8bef8f9ff84c074798d85e8fdffffe87bccffff8d85e8fdffffba70994600e82fb3f9ff8b95e8fdffff8d8528feffffe8ea96f9ff }


condition:
	$a0
}