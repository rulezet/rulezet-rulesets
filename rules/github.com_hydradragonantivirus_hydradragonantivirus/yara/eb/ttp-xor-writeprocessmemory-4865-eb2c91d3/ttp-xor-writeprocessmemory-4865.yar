rule TTP_XOR_WriteProcessMemory_4865 {
  strings:
    $key_4865 = { 1f 17 [2] 2d 35 [2] 2b 00 [2] 05 00 [2] 3a 1c }

  condition:
    any of them
}