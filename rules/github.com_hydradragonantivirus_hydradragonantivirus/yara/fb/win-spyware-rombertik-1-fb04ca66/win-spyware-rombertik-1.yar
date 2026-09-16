rule Win_Spyware_Rombertik_1
{
strings:
	$a0 = { be1e??e80b00ebfeb40eb700b31fcd10c38a044608c07405e8edffebf4c3436172626f6e20637261636b20617474656d70742c206661696c6564 }


condition:
	$a0
}