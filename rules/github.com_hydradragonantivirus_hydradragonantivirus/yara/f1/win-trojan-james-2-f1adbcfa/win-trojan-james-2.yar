rule Win_Trojan_James_2
{
strings:
	$a0 = { 50b8fa0750b83d085051e8022183c40a8bd08bc22505003d0400740533c0e91201f7460602 }


condition:
	$a0
}