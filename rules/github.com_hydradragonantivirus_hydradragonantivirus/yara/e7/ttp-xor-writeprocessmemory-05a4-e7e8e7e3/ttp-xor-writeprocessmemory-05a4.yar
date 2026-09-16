rule TTP_XOR_WriteProcessMemory_05a4 {
  strings:
    $key_05a4 = { 52 d6 [2] 60 f4 [2] 66 c1 [2] 48 c1 [2] 77 dd }

  condition:
    any of them
}