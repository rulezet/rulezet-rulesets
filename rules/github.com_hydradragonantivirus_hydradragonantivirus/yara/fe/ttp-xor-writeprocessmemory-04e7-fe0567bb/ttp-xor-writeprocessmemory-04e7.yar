rule TTP_XOR_WriteProcessMemory_04e7 {
  strings:
    $key_04e7 = { 53 95 [2] 61 b7 [2] 67 82 [2] 49 82 [2] 76 9e }

  condition:
    any of them
}