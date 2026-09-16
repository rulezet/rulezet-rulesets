rule TTP_XOR_WriteProcessMemory_2872 {
  strings:
    $key_2872 = { 7f 00 [2] 4d 22 [2] 4b 17 [2] 65 17 [2] 5a 0b }

  condition:
    any of them
}