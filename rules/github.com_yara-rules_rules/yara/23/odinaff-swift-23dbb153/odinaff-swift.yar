import "pe"
rule Odinaff_swift : malware odinaff swift raw{
        meta:
                author = "@j0sm1"
                date = "2016/10/27"
                description = "Odinaff malware"
                reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2016-083006-4847-99"
                filetype = "binary"

        strings:

                $s1 = "getapula.pdb"
                $i1 = "wtsapi32.dll"
                $i2 = "cmpbk32.dll"
                $i3 = "PostMessageA"
                $i4 = "PeekMessageW"
                $i5 = "DispatchMessageW"
                $i6 = "WTSEnumerateSessionsA"

        condition:
                ($s1 or pe.exports("Tyman32")) and (2 of ($i*))
}