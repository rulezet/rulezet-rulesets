rule TTP_XOR_WriteProcessMemory_e470 {
  strings:
    $key_e470 = { b3 02 [2] 81 20 [2] 87 15 [2] a9 15 [2] 96 09 }

  condition:
    any of them
}