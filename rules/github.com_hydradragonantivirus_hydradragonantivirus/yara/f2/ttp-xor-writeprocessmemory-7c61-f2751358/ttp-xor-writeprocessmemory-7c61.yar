rule TTP_XOR_WriteProcessMemory_7c61 {
  strings:
    $key_7c61 = { 2b 13 [2] 19 31 [2] 1f 04 [2] 31 04 [2] 0e 18 }

  condition:
    any of them
}