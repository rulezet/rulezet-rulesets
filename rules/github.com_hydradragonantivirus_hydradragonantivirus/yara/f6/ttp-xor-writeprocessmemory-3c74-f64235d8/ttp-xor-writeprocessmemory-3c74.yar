rule TTP_XOR_WriteProcessMemory_3c74 {
  strings:
    $key_3c74 = { 6b 06 [2] 59 24 [2] 5f 11 [2] 71 11 [2] 4e 0d }

  condition:
    any of them
}