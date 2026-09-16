rule TTP_XOR_WriteProcessMemory_5ce1 {
  strings:
    $key_5ce1 = { 0b 93 [2] 39 b1 [2] 3f 84 [2] 11 84 [2] 2e 98 }

  condition:
    any of them
}