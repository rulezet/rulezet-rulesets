rule TTP_XOR_WriteProcessMemory_5427 {
  strings:
    $key_5427 = { 03 55 [2] 31 77 [2] 37 42 [2] 19 42 [2] 26 5e }

  condition:
    any of them
}