rule TTP_XOR_WriteProcessMemory_67a4 {
  strings:
    $key_67a4 = { 30 d6 [2] 02 f4 [2] 04 c1 [2] 2a c1 [2] 15 dd }

  condition:
    any of them
}