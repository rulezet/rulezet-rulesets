rule TTP_XOR_WriteProcessMemory_0865 {
  strings:
    $key_0865 = { 5f 17 [2] 6d 35 [2] 6b 00 [2] 45 00 [2] 7a 1c }

  condition:
    any of them
}