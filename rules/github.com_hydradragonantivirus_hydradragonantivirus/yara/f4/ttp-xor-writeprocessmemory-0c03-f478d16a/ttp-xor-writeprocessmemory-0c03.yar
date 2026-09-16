rule TTP_XOR_WriteProcessMemory_0c03 {
  strings:
    $key_0c03 = { 5b 71 [2] 69 53 [2] 6f 66 [2] 41 66 [2] 7e 7a }

  condition:
    any of them
}