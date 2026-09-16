rule TTP_XOR_WriteProcessMemory_ec27 {
  strings:
    $key_ec27 = { bb 55 [2] 89 77 [2] 8f 42 [2] a1 42 [2] 9e 5e }

  condition:
    any of them
}