rule TTP_XOR_WriteProcessMemory_ec31 {
  strings:
    $key_ec31 = { bb 43 [2] 89 61 [2] 8f 54 [2] a1 54 [2] 9e 48 }

  condition:
    any of them
}