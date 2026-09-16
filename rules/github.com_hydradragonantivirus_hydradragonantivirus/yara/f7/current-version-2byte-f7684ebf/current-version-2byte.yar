rule current_version_2byte
{
  meta:
    author = "malvidin"
    description = "Look for two byte xor of target string. Creating ~64K separate rules is faster (~12MB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  strings:
    $target_string = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : (
        uint16be(i) ^ uint16be(i+2) == 0x351b
        and not for 0x2a153 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28, i+30, i+32, i+34, i+36, i+38, i+40 ) : ( 
            uint16be(j) ^ uint16be(j+2) 
        )
        and for 0x2a152 j in ( i+0, i+2, i+4, i+6, i+8, i+10, i+12, i+14, i+16, i+18, i+20, i+22, i+24, i+26, i+28, i+30, i+32, i+34, i+36, i+38, i+40 ) : ( uint16be(j) ^ uint16be(j+2) )
    )
}