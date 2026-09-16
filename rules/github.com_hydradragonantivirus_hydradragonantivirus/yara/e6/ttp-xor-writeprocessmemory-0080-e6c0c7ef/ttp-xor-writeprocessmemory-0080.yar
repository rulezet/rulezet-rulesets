rule TTP_XOR_WriteProcessMemory_0080 {
  strings:
    $key_0080 = { 57 f2 [2] 65 d0 [2] 63 e5 [2] 4d e5 [2] 72 f9 }

  condition:
    any of them
}