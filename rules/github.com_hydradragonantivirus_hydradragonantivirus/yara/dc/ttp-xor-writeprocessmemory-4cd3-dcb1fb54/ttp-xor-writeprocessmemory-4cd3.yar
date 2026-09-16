rule TTP_XOR_WriteProcessMemory_4cd3 {
  strings:
    $key_4cd3 = { 1b a1 [2] 29 83 [2] 2f b6 [2] 01 b6 [2] 3e aa }

  condition:
    any of them
}