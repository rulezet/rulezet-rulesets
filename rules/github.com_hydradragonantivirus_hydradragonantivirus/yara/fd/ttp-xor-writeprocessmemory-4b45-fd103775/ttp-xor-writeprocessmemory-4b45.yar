rule TTP_XOR_WriteProcessMemory_4b45 {
  strings:
    $key_4b45 = { 1c 37 [2] 2e 15 [2] 28 20 [2] 06 20 [2] 39 3c }

  condition:
    any of them
}