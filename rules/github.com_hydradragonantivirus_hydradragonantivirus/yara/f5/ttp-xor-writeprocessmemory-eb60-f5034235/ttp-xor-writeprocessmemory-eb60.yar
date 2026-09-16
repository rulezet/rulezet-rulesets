rule TTP_XOR_WriteProcessMemory_eb60 {
  strings:
    $key_eb60 = { bc 12 [2] 8e 30 [2] 88 05 [2] a6 05 [2] 99 19 }

  condition:
    any of them
}