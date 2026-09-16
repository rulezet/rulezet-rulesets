rule TTP_XOR_WriteProcessMemory_0027 {
  strings:
    $key_0027 = { 57 55 [2] 65 77 [2] 63 42 [2] 4d 42 [2] 72 5e }

  condition:
    any of them
}