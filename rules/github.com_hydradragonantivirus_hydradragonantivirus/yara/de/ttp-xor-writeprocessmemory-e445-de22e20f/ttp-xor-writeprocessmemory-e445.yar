rule TTP_XOR_WriteProcessMemory_e445 {
  strings:
    $key_e445 = { b3 37 [2] 81 15 [2] 87 20 [2] a9 20 [2] 96 3c }

  condition:
    any of them
}