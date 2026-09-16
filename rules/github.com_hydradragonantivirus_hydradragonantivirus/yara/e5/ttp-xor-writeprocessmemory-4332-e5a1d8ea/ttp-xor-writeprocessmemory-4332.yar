rule TTP_XOR_WriteProcessMemory_4332 {
  strings:
    $key_4332 = { 14 40 [2] 26 62 [2] 20 57 [2] 0e 57 [2] 31 4b }

  condition:
    any of them
}