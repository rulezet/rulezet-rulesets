rule TTP_XOR_WriteProcessMemory_5914 {
  strings:
    $key_5914 = { 0e 66 [2] 3c 44 [2] 3a 71 [2] 14 71 [2] 2b 6d }

  condition:
    any of them
}