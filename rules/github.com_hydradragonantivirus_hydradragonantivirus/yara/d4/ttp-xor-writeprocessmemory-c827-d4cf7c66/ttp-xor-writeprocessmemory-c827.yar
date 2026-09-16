rule TTP_XOR_WriteProcessMemory_c827 {
  strings:
    $key_c827 = { 9f 55 [2] ad 77 [2] ab 42 [2] 85 42 [2] ba 5e }

  condition:
    any of them
}