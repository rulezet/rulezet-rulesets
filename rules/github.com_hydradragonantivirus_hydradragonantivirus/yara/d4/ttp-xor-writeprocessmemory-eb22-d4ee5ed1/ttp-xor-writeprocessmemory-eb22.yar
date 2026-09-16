rule TTP_XOR_WriteProcessMemory_eb22 {
  strings:
    $key_eb22 = { bc 50 [2] 8e 72 [2] 88 47 [2] a6 47 [2] 99 5b }

  condition:
    any of them
}