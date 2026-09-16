rule TTP_XOR_WriteProcessMemory_1f96 {
  strings:
    $key_1f96 = { 48 e4 [2] 7a c6 [2] 7c f3 [2] 52 f3 [2] 6d ef }

  condition:
    any of them
}