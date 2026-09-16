rule TTP_XOR_WriteProcessMemory_5642 {
  strings:
    $key_5642 = { 01 30 [2] 33 12 [2] 35 27 [2] 1b 27 [2] 24 3b }

  condition:
    any of them
}