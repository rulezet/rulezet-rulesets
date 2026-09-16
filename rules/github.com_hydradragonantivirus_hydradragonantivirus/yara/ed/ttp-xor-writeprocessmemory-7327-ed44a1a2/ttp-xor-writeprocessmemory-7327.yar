rule TTP_XOR_WriteProcessMemory_7327 {
  strings:
    $key_7327 = { 24 55 [2] 16 77 [2] 10 42 [2] 3e 42 [2] 01 5e }

  condition:
    any of them
}