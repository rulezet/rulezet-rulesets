rule TTP_XOR_WriteProcessMemory_69a2 {
  strings:
    $key_69a2 = { 3e d0 [2] 0c f2 [2] 0a c7 [2] 24 c7 [2] 1b db }

  condition:
    any of them
}