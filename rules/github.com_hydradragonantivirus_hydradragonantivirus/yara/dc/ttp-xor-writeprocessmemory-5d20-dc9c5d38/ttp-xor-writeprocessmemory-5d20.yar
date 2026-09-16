rule TTP_XOR_WriteProcessMemory_5d20 {
  strings:
    $key_5d20 = { 0a 52 [2] 38 70 [2] 3e 45 [2] 10 45 [2] 2f 59 }

  condition:
    any of them
}