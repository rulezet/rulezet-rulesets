rule TTP_XOR_WriteProcessMemory_eda2 {
  strings:
    $key_eda2 = { ba d0 [2] 88 f2 [2] 8e c7 [2] a0 c7 [2] 9f db }

  condition:
    any of them
}