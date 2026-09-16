rule TTP_XOR_WriteProcessMemory_0821 {
  strings:
    $key_0821 = { 5f 53 [2] 6d 71 [2] 6b 44 [2] 45 44 [2] 7a 58 }

  condition:
    any of them
}