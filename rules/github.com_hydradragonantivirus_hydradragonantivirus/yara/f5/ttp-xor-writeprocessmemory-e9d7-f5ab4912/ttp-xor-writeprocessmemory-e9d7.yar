rule TTP_XOR_WriteProcessMemory_e9d7 {
  strings:
    $key_e9d7 = { be a5 [2] 8c 87 [2] 8a b2 [2] a4 b2 [2] 9b ae }

  condition:
    any of them
}