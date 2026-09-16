rule TTP_XOR_WriteProcessMemory_26a4 {
  strings:
    $key_26a4 = { 71 d6 [2] 43 f4 [2] 45 c1 [2] 6b c1 [2] 54 dd }

  condition:
    any of them
}