rule TTP_XOR_WriteProcessMemory_e258 {
  strings:
    $key_e258 = { b5 2a [2] 87 08 [2] 81 3d [2] af 3d [2] 90 21 }

  condition:
    any of them
}