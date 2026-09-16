rule TTP_XOR_WriteProcessMemory_5ca3 {
  strings:
    $key_5ca3 = { 0b d1 [2] 39 f3 [2] 3f c6 [2] 11 c6 [2] 2e da }

  condition:
    any of them
}