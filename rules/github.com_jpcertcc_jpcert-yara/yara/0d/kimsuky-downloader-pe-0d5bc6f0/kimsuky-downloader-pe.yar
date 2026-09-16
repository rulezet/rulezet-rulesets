rule kimsuky_downloader_pe
{
    meta:
        description = "A dotnet executable that downloads the vbs file used by Kimsuky"
        author = "JPCERT/CC Incident Response Group"
        hash = "E5226F945E3EC29868891EDC63E64CAECAE0F9EEF1627EBA826AC08809339A39"

    strings:
        $dotnet1 = "mscoree.dll" ascii
        $dotnet2 = "_CorExeMain" ascii
        $s1 = "powershell.exe" wide
        $s2 = "-windowstyle hidden -c wscript '" wide
        $s3 = "RGVjb2RlID0gIiI6Zm9yIGk" wide
        $s4 = "D:\\work\\Virus\\1_troy\\c#\\pack_2023\\2023-06\\work\\obj\\Debug\\ConsoleApplication1.pdb" ascii
        $s5 = {00 07 11 ?? 25 17 59 13 ?? 91 20 92 00 00 00 40 ?? ?? 00 00 07 11 ?? 91 20 F0 00 00 00 40}

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550 and
        all of ($dotnet*) and
        3 of ($s*)
}