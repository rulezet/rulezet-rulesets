rule TTP_XOR_WriteProcessMemory_e493 {
  strings:
    $key_e493 = { b3 e1 [2] 81 c3 [2] 87 f6 [2] a9 f6 [2] 96 ea }

  condition:
    any of them
}