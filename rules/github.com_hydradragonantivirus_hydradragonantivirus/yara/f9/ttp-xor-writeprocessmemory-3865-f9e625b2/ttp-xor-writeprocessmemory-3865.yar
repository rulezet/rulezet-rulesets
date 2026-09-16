rule TTP_XOR_WriteProcessMemory_3865 {
  strings:
    $key_3865 = { 6f 17 [2] 5d 35 [2] 5b 00 [2] 75 00 [2] 4a 1c }

  condition:
    any of them
}