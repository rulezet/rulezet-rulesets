rule TTP_XOR_WriteProcessMemory_e473 {
  strings:
    $key_e473 = { b3 01 [2] 81 23 [2] 87 16 [2] a9 16 [2] 96 0a }

  condition:
    any of them
}