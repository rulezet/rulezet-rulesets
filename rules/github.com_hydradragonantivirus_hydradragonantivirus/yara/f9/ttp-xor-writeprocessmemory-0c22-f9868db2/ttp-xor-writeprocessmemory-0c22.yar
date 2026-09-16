rule TTP_XOR_WriteProcessMemory_0c22 {
  strings:
    $key_0c22 = { 5b 50 [2] 69 72 [2] 6f 47 [2] 41 47 [2] 7e 5b }

  condition:
    any of them
}