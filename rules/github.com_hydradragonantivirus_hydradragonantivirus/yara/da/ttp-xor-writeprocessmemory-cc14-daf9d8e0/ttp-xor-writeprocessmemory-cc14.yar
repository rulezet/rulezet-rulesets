rule TTP_XOR_WriteProcessMemory_cc14 {
  strings:
    $key_cc14 = { 9b 66 [2] a9 44 [2] af 71 [2] 81 71 [2] be 6d }

  condition:
    any of them
}