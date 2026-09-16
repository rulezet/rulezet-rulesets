rule TTP_XOR_WriteProcessMemory_eb50 {
  strings:
    $key_eb50 = { bc 22 [2] 8e 00 [2] 88 35 [2] a6 35 [2] 99 29 }

  condition:
    any of them
}