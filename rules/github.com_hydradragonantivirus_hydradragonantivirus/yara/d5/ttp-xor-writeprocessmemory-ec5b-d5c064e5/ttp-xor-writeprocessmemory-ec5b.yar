rule TTP_XOR_WriteProcessMemory_ec5b {
  strings:
    $key_ec5b = { bb 29 [2] 89 0b [2] 8f 3e [2] a1 3e [2] 9e 22 }

  condition:
    any of them
}