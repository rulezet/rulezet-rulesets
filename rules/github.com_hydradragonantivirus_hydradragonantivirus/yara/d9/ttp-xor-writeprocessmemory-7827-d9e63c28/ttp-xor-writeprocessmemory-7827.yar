rule TTP_XOR_WriteProcessMemory_7827 {
  strings:
    $key_7827 = { 2f 55 [2] 1d 77 [2] 1b 42 [2] 35 42 [2] 0a 5e }

  condition:
    any of them
}