rule TTP_XOR_WriteProcessMemory_e657 {
  strings:
    $key_e657 = { b1 25 [2] 83 07 [2] 85 32 [2] ab 32 [2] 94 2e }

  condition:
    any of them
}