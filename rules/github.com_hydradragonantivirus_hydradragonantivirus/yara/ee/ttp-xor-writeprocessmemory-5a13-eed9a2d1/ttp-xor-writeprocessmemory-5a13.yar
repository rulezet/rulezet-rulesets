rule TTP_XOR_WriteProcessMemory_5a13 {
  strings:
    $key_5a13 = { 0d 61 [2] 3f 43 [2] 39 76 [2] 17 76 [2] 28 6a }

  condition:
    any of them
}