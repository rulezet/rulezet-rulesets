rule TTP_XOR_WriteProcessMemory_1e08 {
  strings:
    $key_1e08 = { 49 7a [2] 7b 58 [2] 7d 6d [2] 53 6d [2] 6c 71 }

  condition:
    any of them
}