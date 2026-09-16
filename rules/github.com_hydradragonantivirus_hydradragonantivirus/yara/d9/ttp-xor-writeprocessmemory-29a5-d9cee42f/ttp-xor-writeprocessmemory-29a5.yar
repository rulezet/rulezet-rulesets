rule TTP_XOR_WriteProcessMemory_29a5 {
  strings:
    $key_29a5 = { 7e d7 [2] 4c f5 [2] 4a c0 [2] 64 c0 [2] 5b dc }

  condition:
    any of them
}