rule TTP_XOR_WriteProcessMemory_e480 {
  strings:
    $key_e480 = { b3 f2 [2] 81 d0 [2] 87 e5 [2] a9 e5 [2] 96 f9 }

  condition:
    any of them
}