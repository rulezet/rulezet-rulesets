rule TTP_XOR_WriteProcessMemory_26e9 {
  strings:
    $key_26e9 = { 71 9b [2] 43 b9 [2] 45 8c [2] 6b 8c [2] 54 90 }

  condition:
    any of them
}