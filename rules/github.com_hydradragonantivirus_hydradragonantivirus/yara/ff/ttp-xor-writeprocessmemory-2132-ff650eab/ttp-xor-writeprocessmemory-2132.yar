rule TTP_XOR_WriteProcessMemory_2132 {
  strings:
    $key_2132 = { 76 40 [2] 44 62 [2] 42 57 [2] 6c 57 [2] 53 4b }

  condition:
    any of them
}