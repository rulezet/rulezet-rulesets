rule TTP_XOR_WriteProcessMemory_8c27 {
  strings:
    $key_8c27 = { db 55 [2] e9 77 [2] ef 42 [2] c1 42 [2] fe 5e }

  condition:
    any of them
}