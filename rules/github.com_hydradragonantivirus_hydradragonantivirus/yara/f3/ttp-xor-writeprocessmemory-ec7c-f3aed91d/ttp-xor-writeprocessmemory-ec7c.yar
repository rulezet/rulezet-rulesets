rule TTP_XOR_WriteProcessMemory_ec7c {
  strings:
    $key_ec7c = { bb 0e [2] 89 2c [2] 8f 19 [2] a1 19 [2] 9e 05 }

  condition:
    any of them
}