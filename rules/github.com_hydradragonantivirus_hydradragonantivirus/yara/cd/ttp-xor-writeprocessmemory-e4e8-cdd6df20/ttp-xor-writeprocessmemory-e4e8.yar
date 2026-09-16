rule TTP_XOR_WriteProcessMemory_e4e8 {
  strings:
    $key_e4e8 = { b3 9a [2] 81 b8 [2] 87 8d [2] a9 8d [2] 96 91 }

  condition:
    any of them
}