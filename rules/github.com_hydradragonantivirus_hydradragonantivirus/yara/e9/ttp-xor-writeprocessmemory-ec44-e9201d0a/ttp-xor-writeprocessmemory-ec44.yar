rule TTP_XOR_WriteProcessMemory_ec44 {
  strings:
    $key_ec44 = { bb 36 [2] 89 14 [2] 8f 21 [2] a1 21 [2] 9e 3d }

  condition:
    any of them
}