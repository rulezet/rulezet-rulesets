rule Win_Trojan_Lesson_1
{
strings:
	$a0 = { 8945152d03008984a401b440b9ef008d940301cd2126c745150000b440b903008d94a301cd2158 }


condition:
	$a0
}