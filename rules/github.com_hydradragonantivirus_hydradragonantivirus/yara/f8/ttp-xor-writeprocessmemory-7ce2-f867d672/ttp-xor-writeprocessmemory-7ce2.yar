rule TTP_XOR_WriteProcessMemory_7ce2 {
  strings:
    $key_7ce2 = { 2b 90 [2] 19 b2 [2] 1f 87 [2] 31 87 [2] 0e 9b }

  condition:
    any of them
}