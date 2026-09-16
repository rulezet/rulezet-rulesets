rule TTP_XOR_WriteProcessMemory_2187 {
  strings:
    $key_2187 = { 76 f5 [2] 44 d7 [2] 42 e2 [2] 6c e2 [2] 53 fe }

  condition:
    any of them
}