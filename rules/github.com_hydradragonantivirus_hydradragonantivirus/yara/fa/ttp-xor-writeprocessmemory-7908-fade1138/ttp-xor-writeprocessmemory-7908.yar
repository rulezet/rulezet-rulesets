rule TTP_XOR_WriteProcessMemory_7908 {
  strings:
    $key_7908 = { 2e 7a [2] 1c 58 [2] 1a 6d [2] 34 6d [2] 0b 71 }

  condition:
    any of them
}