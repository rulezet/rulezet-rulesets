rule TTP_XOR_WriteProcessMemory_5c74 {
  strings:
    $key_5c74 = { 0b 06 [2] 39 24 [2] 3f 11 [2] 11 11 [2] 2e 0d }

  condition:
    any of them
}