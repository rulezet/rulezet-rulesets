rule TTP_XOR_WriteProcessMemory_1920 {
  strings:
    $key_1920 = { 4e 52 [2] 7c 70 [2] 7a 45 [2] 54 45 [2] 6b 59 }

  condition:
    any of them
}