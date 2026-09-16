rule TTP_XOR_WriteProcessMemory_3727 {
  strings:
    $key_3727 = { 60 55 [2] 52 77 [2] 54 42 [2] 7a 42 [2] 45 5e }

  condition:
    any of them
}