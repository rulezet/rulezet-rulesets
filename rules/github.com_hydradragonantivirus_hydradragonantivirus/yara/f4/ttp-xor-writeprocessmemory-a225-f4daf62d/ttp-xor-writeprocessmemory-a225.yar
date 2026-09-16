rule TTP_XOR_WriteProcessMemory_a225 {
  strings:
    $key_a225 = { f5 57 [2] c7 75 [2] c1 40 [2] ef 40 [2] d0 5c }

  condition:
    any of them
}