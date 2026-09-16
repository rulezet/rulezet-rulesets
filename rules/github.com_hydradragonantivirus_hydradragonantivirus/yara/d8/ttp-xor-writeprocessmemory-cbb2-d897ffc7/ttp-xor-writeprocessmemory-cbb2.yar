rule TTP_XOR_WriteProcessMemory_cbb2 {
  strings:
    $key_cbb2 = { 9c c0 [2] ae e2 [2] a8 d7 [2] 86 d7 [2] b9 cb }

  condition:
    any of them
}