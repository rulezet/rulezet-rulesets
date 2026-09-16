rule TTP_XOR_WriteProcessMemory_5ca2 {
  strings:
    $key_5ca2 = { 0b d0 [2] 39 f2 [2] 3f c7 [2] 11 c7 [2] 2e db }

  condition:
    any of them
}