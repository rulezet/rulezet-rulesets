rule win_64_mem_dump: DMP
{
    meta:
        author = "Jaume Martin"
        file_info = "Windows 64-bit memory dump"

    strings:
        $a = {50 41 47 45 44 55 36 34}

    condition:
       $a at 0
}