rule TTP_XOR_WriteProcessMemory_66e7 {
  strings:
    $key_66e7 = { 31 95 [2] 03 b7 [2] 05 82 [2] 2b 82 [2] 14 9e }

  condition:
    any of them
}