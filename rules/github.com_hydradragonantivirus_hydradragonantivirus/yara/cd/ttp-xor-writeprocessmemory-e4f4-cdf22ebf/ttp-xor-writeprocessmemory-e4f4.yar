rule TTP_XOR_WriteProcessMemory_e4f4 {
  strings:
    $key_e4f4 = { b3 86 [2] 81 a4 [2] 87 91 [2] a9 91 [2] 96 8d }

  condition:
    any of them
}