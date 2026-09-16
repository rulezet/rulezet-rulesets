rule TTP_XOR_WriteProcessMemory_4c74 {
  strings:
    $key_4c74 = { 1b 06 [2] 29 24 [2] 2f 11 [2] 01 11 [2] 3e 0d }

  condition:
    any of them
}