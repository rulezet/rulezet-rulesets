rule TTP_XOR_WriteProcessMemory_eda4 {
  strings:
    $key_eda4 = { ba d6 [2] 88 f4 [2] 8e c1 [2] a0 c1 [2] 9f dd }

  condition:
    any of them
}