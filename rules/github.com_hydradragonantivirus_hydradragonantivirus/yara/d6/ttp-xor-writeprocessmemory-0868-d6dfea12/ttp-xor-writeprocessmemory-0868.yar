rule TTP_XOR_WriteProcessMemory_0868 {
  strings:
    $key_0868 = { 5f 1a [2] 6d 38 [2] 6b 0d [2] 45 0d [2] 7a 11 }

  condition:
    any of them
}