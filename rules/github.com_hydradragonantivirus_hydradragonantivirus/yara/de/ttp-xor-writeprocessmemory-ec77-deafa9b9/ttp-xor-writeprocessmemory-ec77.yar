rule TTP_XOR_WriteProcessMemory_ec77 {
  strings:
    $key_ec77 = { bb 05 [2] 89 27 [2] 8f 12 [2] a1 12 [2] 9e 0e }

  condition:
    any of them
}