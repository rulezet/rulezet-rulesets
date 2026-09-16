rule TTP_XOR_WriteProcessMemory_e627 {
  strings:
    $key_e627 = { b1 55 [2] 83 77 [2] 85 42 [2] ab 42 [2] 94 5e }

  condition:
    any of them
}