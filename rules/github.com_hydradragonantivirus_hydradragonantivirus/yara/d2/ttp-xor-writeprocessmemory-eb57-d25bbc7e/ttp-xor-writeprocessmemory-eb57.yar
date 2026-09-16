rule TTP_XOR_WriteProcessMemory_eb57 {
  strings:
    $key_eb57 = { bc 25 [2] 8e 07 [2] 88 32 [2] a6 32 [2] 99 2e }

  condition:
    any of them
}