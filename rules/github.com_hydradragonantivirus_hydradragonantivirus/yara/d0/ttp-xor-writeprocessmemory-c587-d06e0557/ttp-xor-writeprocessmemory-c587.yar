rule TTP_XOR_WriteProcessMemory_c587 {
  strings:
    $key_c587 = { 92 f5 [2] a0 d7 [2] a6 e2 [2] 88 e2 [2] b7 fe }

  condition:
    any of them
}