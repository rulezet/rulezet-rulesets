rule TTP_XOR_WriteProcessMemory_7fe7 {
  strings:
    $key_7fe7 = { 28 95 [2] 1a b7 [2] 1c 82 [2] 32 82 [2] 0d 9e }

  condition:
    any of them
}