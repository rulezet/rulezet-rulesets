rule TTP_XOR_WriteProcessMemory_ec05 {
  strings:
    $key_ec05 = { bb 77 [2] 89 55 [2] 8f 60 [2] a1 60 [2] 9e 7c }

  condition:
    any of them
}