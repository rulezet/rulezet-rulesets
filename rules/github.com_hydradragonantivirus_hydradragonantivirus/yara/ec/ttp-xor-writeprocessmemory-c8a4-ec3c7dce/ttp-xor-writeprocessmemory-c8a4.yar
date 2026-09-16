rule TTP_XOR_WriteProcessMemory_c8a4 {
  strings:
    $key_c8a4 = { 9f d6 [2] ad f4 [2] ab c1 [2] 85 c1 [2] ba dd }

  condition:
    any of them
}