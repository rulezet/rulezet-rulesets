rule Win_Trojan_Garfio_1
{
strings:
	$a0 = { 53b80242b90000ba0000cd213e8386a301035b53b440b9e8038d960a01cd21ff06eb01e966 }


condition:
	$a0
}