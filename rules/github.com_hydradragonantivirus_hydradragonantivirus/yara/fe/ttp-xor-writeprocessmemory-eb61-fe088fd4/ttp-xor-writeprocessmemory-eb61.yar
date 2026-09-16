rule TTP_XOR_WriteProcessMemory_eb61 {
  strings:
    $key_eb61 = { bc 13 [2] 8e 31 [2] 88 04 [2] a6 04 [2] 99 18 }

  condition:
    any of them
}