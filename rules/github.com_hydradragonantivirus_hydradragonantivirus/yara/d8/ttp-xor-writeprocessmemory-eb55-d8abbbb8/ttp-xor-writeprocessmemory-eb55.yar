rule TTP_XOR_WriteProcessMemory_eb55 {
  strings:
    $key_eb55 = { bc 27 [2] 8e 05 [2] 88 30 [2] a6 30 [2] 99 2c }

  condition:
    any of them
}