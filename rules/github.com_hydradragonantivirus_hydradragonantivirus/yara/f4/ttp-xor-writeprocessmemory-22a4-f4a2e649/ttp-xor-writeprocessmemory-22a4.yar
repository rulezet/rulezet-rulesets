rule TTP_XOR_WriteProcessMemory_22a4 {
  strings:
    $key_22a4 = { 75 d6 [2] 47 f4 [2] 41 c1 [2] 6f c1 [2] 50 dd }

  condition:
    any of them
}