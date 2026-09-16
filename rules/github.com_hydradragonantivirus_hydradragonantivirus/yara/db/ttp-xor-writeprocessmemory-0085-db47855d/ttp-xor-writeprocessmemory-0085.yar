rule TTP_XOR_WriteProcessMemory_0085 {
  strings:
    $key_0085 = { 57 f7 [2] 65 d5 [2] 63 e0 [2] 4d e0 [2] 72 fc }

  condition:
    any of them
}