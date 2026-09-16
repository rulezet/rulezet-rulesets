rule TTP_XOR_WriteProcessMemory_3b27 {
  strings:
    $key_3b27 = { 6c 55 [2] 5e 77 [2] 58 42 [2] 76 42 [2] 49 5e }

  condition:
    any of them
}