rule TTP_XOR_WriteProcessMemory_ec58 {
  strings:
    $key_ec58 = { bb 2a [2] 89 08 [2] 8f 3d [2] a1 3d [2] 9e 21 }

  condition:
    any of them
}