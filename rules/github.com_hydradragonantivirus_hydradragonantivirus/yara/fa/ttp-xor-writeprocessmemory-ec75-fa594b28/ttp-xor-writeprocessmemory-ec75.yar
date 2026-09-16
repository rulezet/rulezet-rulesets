rule TTP_XOR_WriteProcessMemory_ec75 {
  strings:
    $key_ec75 = { bb 07 [2] 89 25 [2] 8f 10 [2] a1 10 [2] 9e 0c }

  condition:
    any of them
}