rule TTP_XOR_WriteProcessMemory_0851 {
  strings:
    $key_0851 = { 5f 23 [2] 6d 01 [2] 6b 34 [2] 45 34 [2] 7a 28 }

  condition:
    any of them
}