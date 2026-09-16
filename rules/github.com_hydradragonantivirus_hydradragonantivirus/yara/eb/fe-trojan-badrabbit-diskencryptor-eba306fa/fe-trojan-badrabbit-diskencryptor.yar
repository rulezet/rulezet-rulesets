rule FE_Trojan_BADRABBIT_DISKENCRYPTOR
    {
        meta:
            author = "muhammad.umair"
            md5 = "b14d8faf7f0cbcfad051cefe5f39645f"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "CryptAcquireContextW" fullword
            $api2 = "CryptEncrypt" fullword
            $api3 = "NetWkstaGetInfo" fullword
            $decrypt_seq = { 89 5D EC 78 10 7F 07 3D 00 00 00 01 76 07 B8 00 00 00 01 EB 07 C7 45 EC 01 00 00 00 53 50 53 6A 04 53 8B F8 56 89 45 FC 89 7D E8 FF 15 ?? ?? ?? ?? 8B D8 85 DB 74 5F }
            $msg1 = "Disk decryption progress..." ascii fullword wide
            $task_fmt_str = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" ascii fullword wide
            $tok1 = "\\\\.\\dcrypt" ascii fullword wide
            $tok2 = "C:\\Windows\\cscc.dat" ascii fullword wide
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 150KB and all of them
    }