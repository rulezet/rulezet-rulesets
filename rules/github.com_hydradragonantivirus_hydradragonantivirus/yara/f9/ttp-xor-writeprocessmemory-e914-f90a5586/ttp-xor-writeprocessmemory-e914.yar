rule TTP_XOR_WriteProcessMemory_e914 {
  strings:
    $key_e914 = { be 66 [2] 8c 44 [2] 8a 71 [2] a4 71 [2] 9b 6d }

  condition:
    any of them
}