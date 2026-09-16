rule cerber3{
meta:
  author = "pekeinfo"
  date = "2016-09-09"
  description = "Cerber3 "
strings:
  $a = {00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 03 6A  01 8B 85}
  $b = {68 3B DB 00 00 ?? ?? ?? ?? 00 ?? FF 15}
  
condition:
  1 of them 
}