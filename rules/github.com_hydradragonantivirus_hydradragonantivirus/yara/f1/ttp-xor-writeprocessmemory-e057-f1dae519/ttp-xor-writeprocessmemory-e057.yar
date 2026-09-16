rule TTP_XOR_WriteProcessMemory_e057 {
  strings:
    $key_e057 = { b7 25 [2] 85 07 [2] 83 32 [2] ad 32 [2] 92 2e }

  condition:
    any of them
}