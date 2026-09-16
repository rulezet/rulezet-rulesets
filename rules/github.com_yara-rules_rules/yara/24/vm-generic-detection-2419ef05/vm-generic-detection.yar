rule VM_Generic_Detection : AntiVM
{
    meta:
        description = "Tries to detect virtualized environments"
    strings:
        $a0 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $a1 = "HARDWARE\\Description\\System" nocase wide ascii
        $a2 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" nocase wide ascii
        $a3 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" nocase wide ascii
        $redpill = { 0F 01 0D 00 00 00 00 C3 }         
                $teslacrypt1 = { D1 29 06 E3 E5 27 CE 11 87 5D 00 60 8C B7 80 66 }         $teslacrypt2 = { B3 EB 36 E4 4F 52 CE 11 9F 53 00 20 AF 0B A7 70 }         
    condition:
        any of ($a*) or $redpill or all of ($teslacrypt*)
}