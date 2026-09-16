rule TTP_XOR_WriteProcessMemory_ec47 {
  strings:
    $key_ec47 = { bb 35 [2] 89 17 [2] 8f 22 [2] a1 22 [2] 9e 3e }

  condition:
    any of them
}