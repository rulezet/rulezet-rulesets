rule TTP_XOR_WriteProcessMemory_ec6f {
  strings:
    $key_ec6f = { bb 1d [2] 89 3f [2] 8f 0a [2] a1 0a [2] 9e 16 }

  condition:
    any of them
}