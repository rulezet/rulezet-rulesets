rule TTP_XOR_WriteProcessMemory_d387 {
  strings:
    $key_d387 = { 84 f5 [2] b6 d7 [2] b0 e2 [2] 9e e2 [2] a1 fe }

  condition:
    any of them
}