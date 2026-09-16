rule TTP_XOR_WriteProcessMemory_d487 {
  strings:
    $key_d487 = { 83 f5 [2] b1 d7 [2] b7 e2 [2] 99 e2 [2] a6 fe }

  condition:
    any of them
}