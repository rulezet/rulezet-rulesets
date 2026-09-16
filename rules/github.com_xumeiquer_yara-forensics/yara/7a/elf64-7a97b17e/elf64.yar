rule elf64: ELF64
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 7F 45 4C 46 }
	$b = "linux_amd64"
	$c = "linux-x86-64"

    condition:
       $a at 0 and ($b or $c)
}