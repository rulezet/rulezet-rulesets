rule TTP_XOR_WriteProcessMemory_7c03 {
  strings:
    $key_7c03 = { 2b 71 [2] 19 53 [2] 1f 66 [2] 31 66 [2] 0e 7a }

  condition:
    any of them
}