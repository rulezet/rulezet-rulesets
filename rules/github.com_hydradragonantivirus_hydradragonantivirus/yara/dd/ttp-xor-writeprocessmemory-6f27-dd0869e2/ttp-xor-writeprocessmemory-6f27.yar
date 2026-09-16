rule TTP_XOR_WriteProcessMemory_6f27 {
  strings:
    $key_6f27 = { 38 55 [2] 0a 77 [2] 0c 42 [2] 22 42 [2] 1d 5e }

  condition:
    any of them
}