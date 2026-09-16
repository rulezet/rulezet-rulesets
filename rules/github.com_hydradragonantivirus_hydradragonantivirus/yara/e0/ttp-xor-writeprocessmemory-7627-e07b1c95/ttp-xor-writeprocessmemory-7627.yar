rule TTP_XOR_WriteProcessMemory_7627 {
  strings:
    $key_7627 = { 21 55 [2] 13 77 [2] 15 42 [2] 3b 42 [2] 04 5e }

  condition:
    any of them
}