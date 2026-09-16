rule TTP_XOR_WriteProcessMemory_ede4 {
  strings:
    $key_ede4 = { ba 96 [2] 88 b4 [2] 8e 81 [2] a0 81 [2] 9f 9d }

  condition:
    any of them
}