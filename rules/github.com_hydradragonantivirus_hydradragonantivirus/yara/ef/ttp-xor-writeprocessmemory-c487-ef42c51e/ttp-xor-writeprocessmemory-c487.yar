rule TTP_XOR_WriteProcessMemory_c487 {
  strings:
    $key_c487 = { 93 f5 [2] a1 d7 [2] a7 e2 [2] 89 e2 [2] b6 fe }

  condition:
    any of them
}