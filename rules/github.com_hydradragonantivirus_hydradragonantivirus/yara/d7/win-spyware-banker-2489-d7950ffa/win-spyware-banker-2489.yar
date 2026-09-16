rule Win_Spyware_Banker_2489
{
strings:
	$a0 = { 0c699542d853375b5c85c35dc84e1c472f1e8e50efe6b0451f0e1febc0d39ef8ebf39f7e9346466f337b3f7d46f0948f04c5baf4151c16a1af1a6e8b3ca68eaf420e9e2c6e6fd4aa958c }


condition:
	$a0
}