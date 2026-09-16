rule TTP_XOR_WriteProcessMemory_5961 {
  strings:
    $key_5961 = { 0e 13 [2] 3c 31 [2] 3a 04 [2] 14 04 [2] 2b 18 }

  condition:
    any of them
}