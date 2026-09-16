rule exe: EXE
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4D 5A }
	$b = "!This program cannot be run in DOS mode."

    condition:
       $a at 0 and for all of ($b): (@ > @a)
}