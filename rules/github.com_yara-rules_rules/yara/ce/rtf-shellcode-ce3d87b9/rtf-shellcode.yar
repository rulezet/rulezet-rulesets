rule RTF_Shellcode : maldoc
{
    meta:

        author = "RSA-IR – Jared Greenhill"
        date = "01/21/13"
        description = "identifies RTF's with potential shellcode"
            filetype = "RTF"

    strings:
        $rtfmagic={7B 5C 72 74 66}
        
        $scregex=/(90){2,20}/

    condition:

        ($rtfmagic at 0) and ($scregex)
}