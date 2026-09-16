rule TTP_XOR_WriteProcessMemory_1018 {
  strings:
    $key_1018 = { 47 6a [2] 75 48 [2] 73 7d [2] 5d 7d [2] 62 61 }

  condition:
    any of them
}