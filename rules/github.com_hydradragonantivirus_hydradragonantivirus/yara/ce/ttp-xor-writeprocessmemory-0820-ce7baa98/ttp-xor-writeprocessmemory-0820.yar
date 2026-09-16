rule TTP_XOR_WriteProcessMemory_0820 {
  strings:
    $key_0820 = { 5f 52 [2] 6d 70 [2] 6b 45 [2] 45 45 [2] 7a 59 }

  condition:
    any of them
}