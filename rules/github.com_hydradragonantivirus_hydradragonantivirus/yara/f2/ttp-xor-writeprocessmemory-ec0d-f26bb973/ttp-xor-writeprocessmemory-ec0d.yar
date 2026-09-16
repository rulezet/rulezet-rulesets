rule TTP_XOR_WriteProcessMemory_ec0d {
  strings:
    $key_ec0d = { bb 7f [2] 89 5d [2] 8f 68 [2] a1 68 [2] 9e 74 }

  condition:
    any of them
}