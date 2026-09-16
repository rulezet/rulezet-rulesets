rule TTP_XOR_WriteProcessMemory_7577 {
  strings:
    $key_7577 = { 22 05 [2] 10 27 [2] 16 12 [2] 38 12 [2] 07 0e }

  condition:
    any of them
}