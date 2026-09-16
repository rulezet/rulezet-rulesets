rule TTP_XOR_WriteProcessMemory_e401 {
  strings:
    $key_e401 = { b3 73 [2] 81 51 [2] 87 64 [2] a9 64 [2] 96 78 }

  condition:
    any of them
}