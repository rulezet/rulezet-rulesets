rule TTP_XOR_WriteProcessMemory_5c27 {
  strings:
    $key_5c27 = { 0b 55 [2] 39 77 [2] 3f 42 [2] 11 42 [2] 2e 5e }

  condition:
    any of them
}