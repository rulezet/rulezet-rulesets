rule TTP_XOR_WriteProcessMemory_0db5 {
  strings:
    $key_0db5 = { 5a c7 [2] 68 e5 [2] 6e d0 [2] 40 d0 [2] 7f cc }

  condition:
    any of them
}