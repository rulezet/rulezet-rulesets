rule TTP_XOR_WriteProcessMemory_f787 {
  strings:
    $key_f787 = { a0 f5 [2] 92 d7 [2] 94 e2 [2] ba e2 [2] 85 fe }

  condition:
    any of them
}