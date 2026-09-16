rule TTP_XOR_WriteProcessMemory_e612 {
  strings:
    $key_e612 = { b1 60 [2] 83 42 [2] 85 77 [2] ab 77 [2] 94 6b }

  condition:
    any of them
}