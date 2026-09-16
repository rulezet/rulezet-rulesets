rule TTP_XOR_WriteProcessMemory_1f20 {
  strings:
    $key_1f20 = { 48 52 [2] 7a 70 [2] 7c 45 [2] 52 45 [2] 6d 59 }

  condition:
    any of them
}