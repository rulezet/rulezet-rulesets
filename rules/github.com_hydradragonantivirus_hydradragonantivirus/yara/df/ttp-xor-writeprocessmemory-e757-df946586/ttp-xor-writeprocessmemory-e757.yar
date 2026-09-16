rule TTP_XOR_WriteProcessMemory_e757 {
  strings:
    $key_e757 = { b0 25 [2] 82 07 [2] 84 32 [2] aa 32 [2] 95 2e }

  condition:
    any of them
}