rule TTP_XOR_WriteProcessMemory_0477 {
  strings:
    $key_0477 = { 53 05 [2] 61 27 [2] 67 12 [2] 49 12 [2] 76 0e }

  condition:
    any of them
}