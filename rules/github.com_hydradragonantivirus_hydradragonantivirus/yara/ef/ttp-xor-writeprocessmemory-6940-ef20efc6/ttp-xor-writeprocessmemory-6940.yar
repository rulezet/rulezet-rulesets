rule TTP_XOR_WriteProcessMemory_6940 {
  strings:
    $key_6940 = { 3e 32 [2] 0c 10 [2] 0a 25 [2] 24 25 [2] 1b 39 }

  condition:
    any of them
}