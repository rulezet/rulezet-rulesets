rule Win_Spyware_Banker_1283
{
strings:
	$a0 = { 9b6edb71dd948a810c0923b2a4f6910b45d857e53617fe753014a8263eed2d46ee0a7b820d9f4a3f0591ca77d150a6b6ec2d566fb376ed98d4f53c736635e12424fec0d0 }


condition:
	$a0
}