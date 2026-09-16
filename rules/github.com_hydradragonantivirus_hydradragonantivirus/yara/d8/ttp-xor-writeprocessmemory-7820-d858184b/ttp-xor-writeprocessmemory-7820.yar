rule TTP_XOR_WriteProcessMemory_7820 {
  strings:
    $key_7820 = { 2f 52 [2] 1d 70 [2] 1b 45 [2] 35 45 [2] 0a 59 }

  condition:
    any of them
}