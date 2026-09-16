rule apt32_macos_backdoor_2019_encryption_key {
  meta:
    report = "https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/"

  strings:
    $key1 = { 9D 72 74 AD 7B CE F0 DE D2 9B DB B4 28 C2 51 DF 8B 35 0B 92 }
    $key2 = { 2c e4 25 29 5e 2a 20 40 9c a5 13 1e 61 1e 51 6f 2c b7 a7 7f }
    $key3 = { 8b b2 c4 67 56 5c 63 42 8e f0 cf c5 f4 8d 87 ae 58 0c 5b a4 }
    $ccc  = "CCCrypt" ascii

  condition:
    (uint16(0) == 0xfacf or uint16(0) == 0xface) and $ccc and any of ($key*)
}