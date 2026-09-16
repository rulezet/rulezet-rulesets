rule TTP_XOR_WriteProcessMemory_4c03 {
  strings:
    $key_4c03 = { 1b 71 [2] 29 53 [2] 2f 66 [2] 01 66 [2] 3e 7a }

  condition:
    any of them
}