rule TTP_XOR_WriteProcessMemory_39d7 {
  strings:
    $key_39d7 = { 6e a5 [2] 5c 87 [2] 5a b2 [2] 74 b2 [2] 4b ae }

  condition:
    any of them
}