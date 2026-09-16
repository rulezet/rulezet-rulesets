rule finppy_linux_coremodule {
  meta:
    description = "Rule for FinSpy Linux core module x86 or x64"
    author      = "Etienne Maynier, Amnesty Tech"

  strings:
    $s1  = "ps auxww | grep -iEe 'bt-scan' | grep -v -e grep" ascii
    $s2  = "ls /sys/class/net/ 2>/dev/null | awk '{printf (\"%s\n\", $1)}' 2>/dev/null" ascii
    $s3  = "cat /sys/class/net/eth?/address 2>/dev/null" ascii
    $s4  = "dmesg --notime 2>/dev/null | grep -i \"cpu\" | grep -i \"virtual\"" ascii
    $s5  = "/etc/hostname-merlin" ascii
    $s6  = "@%02X%X%c%08X.dat" ascii
    $s7  = "%s/.bash_profile1" ascii
    $s8  = "%s/.kde4/share/config" ascii
    $s9  = "ls /dev/disk/by-id/ 2>/dev/null" ascii
    $s10 = "/index.php HTTP/1.1" ascii

  condition:
    uint16(0) == 0x457F and 8 of them
}