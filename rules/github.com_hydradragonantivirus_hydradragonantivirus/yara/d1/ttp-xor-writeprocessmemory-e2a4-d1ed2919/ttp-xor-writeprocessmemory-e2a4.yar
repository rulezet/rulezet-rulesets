rule TTP_XOR_WriteProcessMemory_e2a4 {
  strings:
    $key_e2a4 = { b5 d6 [2] 87 f4 [2] 81 c1 [2] af c1 [2] 90 dd }

  condition:
    any of them
}