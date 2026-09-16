rule TTP_XOR_WriteProcessMemory_0327 {
  strings:
    $key_0327 = { 54 55 [2] 66 77 [2] 60 42 [2] 4e 42 [2] 71 5e }

  condition:
    any of them
}