rule TTP_XOR_WriteProcessMemory_0387 {
  strings:
    $key_0387 = { 54 f5 [2] 66 d7 [2] 60 e2 [2] 4e e2 [2] 71 fe }

  condition:
    any of them
}