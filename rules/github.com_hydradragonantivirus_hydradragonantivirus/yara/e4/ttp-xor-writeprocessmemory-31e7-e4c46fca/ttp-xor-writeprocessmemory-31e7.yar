rule TTP_XOR_WriteProcessMemory_31e7 {
  strings:
    $key_31e7 = { 66 95 [2] 54 b7 [2] 52 82 [2] 7c 82 [2] 43 9e }

  condition:
    any of them
}