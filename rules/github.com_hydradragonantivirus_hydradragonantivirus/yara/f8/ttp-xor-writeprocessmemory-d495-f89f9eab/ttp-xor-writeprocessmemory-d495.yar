rule TTP_XOR_WriteProcessMemory_d495 {
  strings:
    $key_d495 = { 83 e7 [2] b1 c5 [2] b7 f0 [2] 99 f0 [2] a6 ec }

  condition:
    any of them
}