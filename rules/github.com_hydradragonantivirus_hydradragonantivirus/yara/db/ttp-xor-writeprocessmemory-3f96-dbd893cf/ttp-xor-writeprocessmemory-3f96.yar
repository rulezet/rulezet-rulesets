rule TTP_XOR_WriteProcessMemory_3f96 {
  strings:
    $key_3f96 = { 68 e4 [2] 5a c6 [2] 5c f3 [2] 72 f3 [2] 4d ef }

  condition:
    any of them
}