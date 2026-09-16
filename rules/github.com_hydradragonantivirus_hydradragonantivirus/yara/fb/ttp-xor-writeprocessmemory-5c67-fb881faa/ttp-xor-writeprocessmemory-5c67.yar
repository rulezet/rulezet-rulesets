rule TTP_XOR_WriteProcessMemory_5c67 {
  strings:
    $key_5c67 = { 0b 15 [2] 39 37 [2] 3f 02 [2] 11 02 [2] 2e 1e }

  condition:
    any of them
}