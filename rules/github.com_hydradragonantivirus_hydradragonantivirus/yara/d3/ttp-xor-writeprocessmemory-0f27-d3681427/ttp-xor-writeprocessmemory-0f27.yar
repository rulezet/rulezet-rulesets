rule TTP_XOR_WriteProcessMemory_0f27 {
  strings:
    $key_0f27 = { 58 55 [2] 6a 77 [2] 6c 42 [2] 42 42 [2] 7d 5e }

  condition:
    any of them
}