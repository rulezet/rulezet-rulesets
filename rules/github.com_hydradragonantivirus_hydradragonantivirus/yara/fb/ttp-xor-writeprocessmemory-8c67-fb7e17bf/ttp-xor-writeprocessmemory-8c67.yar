rule TTP_XOR_WriteProcessMemory_8c67 {
  strings:
    $key_8c67 = { db 15 [2] e9 37 [2] ef 02 [2] c1 02 [2] fe 1e }

  condition:
    any of them
}