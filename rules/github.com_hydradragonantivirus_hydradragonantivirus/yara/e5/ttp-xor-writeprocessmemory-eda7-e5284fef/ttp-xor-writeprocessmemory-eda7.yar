rule TTP_XOR_WriteProcessMemory_eda7 {
  strings:
    $key_eda7 = { ba d5 [2] 88 f7 [2] 8e c2 [2] a0 c2 [2] 9f de }

  condition:
    any of them
}