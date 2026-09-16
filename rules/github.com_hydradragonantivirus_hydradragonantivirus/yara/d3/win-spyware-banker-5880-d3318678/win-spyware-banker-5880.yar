rule Win_Spyware_Banker_5880
{
strings:
	$a0 = { c4cfb857f4929daa02601d3f449c02a90a631f5a1145a2c302a7f41b00d6ea5eb212a9d28795c4654acf2c904d07b8fc40649a0b018d23fcfd0032873937ca23dc9ea7cd }


condition:
	$a0
}