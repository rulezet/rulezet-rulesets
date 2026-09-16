rule TTP_XOR_WriteProcessMemory_7920 {
  strings:
    $key_7920 = { 2e 52 [2] 1c 70 [2] 1a 45 [2] 34 45 [2] 0b 59 }

  condition:
    any of them
}