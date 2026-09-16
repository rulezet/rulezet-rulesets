rule TTP_XOR_WriteProcessMemory_4220 {
  strings:
    $key_4220 = { 15 52 [2] 27 70 [2] 21 45 [2] 0f 45 [2] 30 59 }

  condition:
    any of them
}