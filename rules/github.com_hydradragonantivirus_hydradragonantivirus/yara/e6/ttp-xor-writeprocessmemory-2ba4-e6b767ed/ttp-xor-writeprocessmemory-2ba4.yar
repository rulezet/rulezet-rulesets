rule TTP_XOR_WriteProcessMemory_2ba4 {
  strings:
    $key_2ba4 = { 7c d6 [2] 4e f4 [2] 48 c1 [2] 66 c1 [2] 59 dd }

  condition:
    any of them
}