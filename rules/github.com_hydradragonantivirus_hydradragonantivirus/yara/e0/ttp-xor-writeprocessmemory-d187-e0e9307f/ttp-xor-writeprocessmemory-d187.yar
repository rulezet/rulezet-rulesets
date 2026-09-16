rule TTP_XOR_WriteProcessMemory_d187 {
  strings:
    $key_d187 = { 86 f5 [2] b4 d7 [2] b2 e2 [2] 9c e2 [2] a3 fe }

  condition:
    any of them
}