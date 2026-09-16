rule TTP_XOR_WriteProcessMemory_1231 {
  strings:
    $key_1231 = { 45 43 [2] 77 61 [2] 71 54 [2] 5f 54 [2] 60 48 }

  condition:
    any of them
}