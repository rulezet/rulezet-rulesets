rule TTP_XOR_WriteProcessMemory_ec02 {
  strings:
    $key_ec02 = { bb 70 [2] 89 52 [2] 8f 67 [2] a1 67 [2] 9e 7b }

  condition:
    any of them
}