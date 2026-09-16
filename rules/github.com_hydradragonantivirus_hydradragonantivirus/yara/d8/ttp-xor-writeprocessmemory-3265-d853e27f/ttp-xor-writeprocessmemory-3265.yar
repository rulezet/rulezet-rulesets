rule TTP_XOR_WriteProcessMemory_3265 {
  strings:
    $key_3265 = { 65 17 [2] 57 35 [2] 51 00 [2] 7f 00 [2] 40 1c }

  condition:
    any of them
}