rule TTP_XOR_WriteProcessMemory_5d53 {
  strings:
    $key_5d53 = { 0a 21 [2] 38 03 [2] 3e 36 [2] 10 36 [2] 2f 2a }

  condition:
    any of them
}