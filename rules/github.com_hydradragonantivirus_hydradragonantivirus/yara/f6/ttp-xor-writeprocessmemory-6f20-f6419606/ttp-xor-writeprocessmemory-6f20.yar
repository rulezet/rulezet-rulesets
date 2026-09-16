rule TTP_XOR_WriteProcessMemory_6f20 {
  strings:
    $key_6f20 = { 38 52 [2] 0a 70 [2] 0c 45 [2] 22 45 [2] 1d 59 }

  condition:
    any of them
}