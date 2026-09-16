rule TTP_XOR_WriteProcessMemory_2f96 {
  strings:
    $key_2f96 = { 78 e4 [2] 4a c6 [2] 4c f3 [2] 62 f3 [2] 5d ef }

  condition:
    any of them
}