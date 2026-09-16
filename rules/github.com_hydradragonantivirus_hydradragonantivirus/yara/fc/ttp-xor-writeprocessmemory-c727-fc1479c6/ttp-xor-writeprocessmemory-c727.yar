rule TTP_XOR_WriteProcessMemory_c727 {
  strings:
    $key_c727 = { 90 55 [2] a2 77 [2] a4 42 [2] 8a 42 [2] b5 5e }

  condition:
    any of them
}