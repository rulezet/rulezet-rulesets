rule TTP_XOR_WriteProcessMemory_5d45 {
  strings:
    $key_5d45 = { 0a 37 [2] 38 15 [2] 3e 20 [2] 10 20 [2] 2f 3c }

  condition:
    any of them
}