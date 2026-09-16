rule TTP_XOR_WriteProcessMemory_06e2 {
  strings:
    $key_06e2 = { 51 90 [2] 63 b2 [2] 65 87 [2] 4b 87 [2] 74 9b }

  condition:
    any of them
}