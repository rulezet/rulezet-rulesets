rule TTP_XOR_WriteProcessMemory_4704 {
  strings:
    $key_4704 = { 10 76 [2] 22 54 [2] 24 61 [2] 0a 61 [2] 35 7d }

  condition:
    any of them
}