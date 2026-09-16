rule TTP_XOR_WriteProcessMemory_31a4 {
  strings:
    $key_31a4 = { 66 d6 [2] 54 f4 [2] 52 c1 [2] 7c c1 [2] 43 dd }

  condition:
    any of them
}