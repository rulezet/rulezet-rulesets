rule TTP_XOR_WriteProcessMemory_0861 {
  strings:
    $key_0861 = { 5f 13 [2] 6d 31 [2] 6b 04 [2] 45 04 [2] 7a 18 }

  condition:
    any of them
}