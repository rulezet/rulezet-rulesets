rule TTP_XOR_WriteProcessMemory_f500 {
  strings:
    $key_f500 = { a2 72 [2] 90 50 [2] 96 65 [2] b8 65 [2] 87 79 }

  condition:
    any of them
}