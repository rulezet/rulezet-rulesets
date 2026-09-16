rule TTP_XOR_WriteProcessMemory_a2e5 {
  strings:
    $key_a2e5 = { f5 97 [2] c7 b5 [2] c1 80 [2] ef 80 [2] d0 9c }

  condition:
    any of them
}