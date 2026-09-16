rule TTP_XOR_WriteProcessMemory_3318 {
  strings:
    $key_3318 = { 64 6a [2] 56 48 [2] 50 7d [2] 7e 7d [2] 41 61 }

  condition:
    any of them
}