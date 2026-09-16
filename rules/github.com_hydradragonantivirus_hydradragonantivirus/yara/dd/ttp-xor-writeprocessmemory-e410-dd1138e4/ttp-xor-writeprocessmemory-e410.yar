rule TTP_XOR_WriteProcessMemory_e410 {
  strings:
    $key_e410 = { b3 62 [2] 81 40 [2] 87 75 [2] a9 75 [2] 96 69 }

  condition:
    any of them
}