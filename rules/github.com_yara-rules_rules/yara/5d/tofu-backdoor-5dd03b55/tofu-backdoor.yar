rule Tofu_Backdoor
{
meta:
        author = "Cylance Spear Team"
        reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
strings:
	$a = "Cookies: Sym1.0"
	$b = "\\\\.\\pipe\\1[12345678]"
	$c = {66 0F FC C1 0F 11 40 D0 0F 10 40 D0 66 0F EF C2 0F 11 40 D0 0F 10 40 E0}
condition:
	$a or $b or $c
}