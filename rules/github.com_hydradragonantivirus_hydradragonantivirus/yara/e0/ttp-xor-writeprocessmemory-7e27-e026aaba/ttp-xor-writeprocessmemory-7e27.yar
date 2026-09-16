rule TTP_XOR_WriteProcessMemory_7e27 {
  strings:
    $key_7e27 = { 29 55 [2] 1b 77 [2] 1d 42 [2] 33 42 [2] 0c 5e }

  condition:
    any of them
}