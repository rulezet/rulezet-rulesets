rule TTP_XOR_WriteProcessMemory_4018 {
  strings:
    $key_4018 = { 17 6a [2] 25 48 [2] 23 7d [2] 0d 7d [2] 32 61 }

  condition:
    any of them
}