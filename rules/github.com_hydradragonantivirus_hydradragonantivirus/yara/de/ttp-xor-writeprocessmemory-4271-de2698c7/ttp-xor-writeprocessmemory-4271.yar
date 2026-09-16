rule TTP_XOR_WriteProcessMemory_4271 {
  strings:
    $key_4271 = { 15 03 [2] 27 21 [2] 21 14 [2] 0f 14 [2] 30 08 }

  condition:
    any of them
}