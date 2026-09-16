rule TTP_XOR_WriteProcessMemory_1930 {
  strings:
    $key_1930 = { 4e 42 [2] 7c 60 [2] 7a 55 [2] 54 55 [2] 6b 49 }

  condition:
    any of them
}