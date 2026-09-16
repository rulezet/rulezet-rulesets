rule TTP_XOR_WriteProcessMemory_ec07 {
  strings:
    $key_ec07 = { bb 75 [2] 89 57 [2] 8f 62 [2] a1 62 [2] 9e 7e }

  condition:
    any of them
}