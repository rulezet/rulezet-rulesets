rule TTP_XOR_WriteProcessMemory_2327 {
  strings:
    $key_2327 = { 74 55 [2] 46 77 [2] 40 42 [2] 6e 42 [2] 51 5e }

  condition:
    any of them
}