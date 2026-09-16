rule days_of_yara_url_4byte 
{
  meta:
    author = "malvidin"
    description = "Look for four byte xor of target string. Creating ~4G separate rules would probably be faster (~860 GB rule file)"
    warning = "Loops over entire file, very poor performance."
    target_string = "https://github.com/100DaysofYARA"
  strings:
    $target_string = /https:\/\/github\.com\/100DaysofYARA/
  condition:
    not $target_string and
    for any i in ( 0 .. filesize ) : ( 
      uint32be(i) ^ uint32be(i+4) == 0x1b4e5b5f
      and not for 0x1248ee582 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24 ) : ( 
        uint32be(j) ^ uint32be(j+4) 
      )
      and for 0x1248ee581 j in ( i+0, i+4, i+8, i+12, i+16, i+20, i+24 ) : ( 
        uint32be(j) ^ uint32be(j+4)
      )
    )
}