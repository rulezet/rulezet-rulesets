rule TTP_XOR_WriteProcessMemory_66a4 {
  strings:
    $key_66a4 = { 31 d6 [2] 03 f4 [2] 05 c1 [2] 2b c1 [2] 14 dd }

  condition:
    any of them
}