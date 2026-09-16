rule TTP_XOR_WriteProcessMemory_2e27 {
  strings:
    $key_2e27 = { 79 55 [2] 4b 77 [2] 4d 42 [2] 63 42 [2] 5c 5e }

  condition:
    any of them
}