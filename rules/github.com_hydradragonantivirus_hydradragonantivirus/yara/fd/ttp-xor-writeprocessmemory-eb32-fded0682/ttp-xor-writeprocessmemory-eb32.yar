rule TTP_XOR_WriteProcessMemory_eb32 {
  strings:
    $key_eb32 = { bc 40 [2] 8e 62 [2] 88 57 [2] a6 57 [2] 99 4b }

  condition:
    any of them
}