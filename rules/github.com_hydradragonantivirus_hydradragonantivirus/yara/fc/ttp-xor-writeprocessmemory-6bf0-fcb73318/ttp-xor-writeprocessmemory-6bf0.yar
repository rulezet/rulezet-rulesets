rule TTP_XOR_WriteProcessMemory_6bf0 {
  strings:
    $key_6bf0 = { 3c 82 [2] 0e a0 [2] 08 95 [2] 26 95 [2] 19 89 }

  condition:
    any of them
}