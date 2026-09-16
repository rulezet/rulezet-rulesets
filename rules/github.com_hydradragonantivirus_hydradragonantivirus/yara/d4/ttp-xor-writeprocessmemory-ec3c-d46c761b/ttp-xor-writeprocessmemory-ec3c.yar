rule TTP_XOR_WriteProcessMemory_ec3c {
  strings:
    $key_ec3c = { bb 4e [2] 89 6c [2] 8f 59 [2] a1 59 [2] 9e 45 }

  condition:
    any of them
}