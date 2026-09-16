rule TTP_XOR_WriteProcessMemory_eb33 {
  strings:
    $key_eb33 = { bc 41 [2] 8e 63 [2] 88 56 [2] a6 56 [2] 99 4a }

  condition:
    any of them
}