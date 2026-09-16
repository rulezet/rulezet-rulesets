rule TTP_XOR_WriteProcessMemory_7d27 {
  strings:
    $key_7d27 = { 2a 55 [2] 18 77 [2] 1e 42 [2] 30 42 [2] 0f 5e }

  condition:
    any of them
}