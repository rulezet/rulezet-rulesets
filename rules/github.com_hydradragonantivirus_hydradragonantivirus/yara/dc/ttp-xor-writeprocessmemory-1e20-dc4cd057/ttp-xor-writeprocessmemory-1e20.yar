rule TTP_XOR_WriteProcessMemory_1e20 {
  strings:
    $key_1e20 = { 49 52 [2] 7b 70 [2] 7d 45 [2] 53 45 [2] 6c 59 }

  condition:
    any of them
}