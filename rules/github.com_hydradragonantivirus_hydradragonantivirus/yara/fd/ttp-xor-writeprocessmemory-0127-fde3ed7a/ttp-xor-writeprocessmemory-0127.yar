rule TTP_XOR_WriteProcessMemory_0127 {
  strings:
    $key_0127 = { 56 55 [2] 64 77 [2] 62 42 [2] 4c 42 [2] 73 5e }

  condition:
    any of them
}