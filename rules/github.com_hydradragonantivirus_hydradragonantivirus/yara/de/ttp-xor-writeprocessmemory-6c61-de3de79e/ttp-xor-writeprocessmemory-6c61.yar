rule TTP_XOR_WriteProcessMemory_6c61 {
  strings:
    $key_6c61 = { 3b 13 [2] 09 31 [2] 0f 04 [2] 21 04 [2] 1e 18 }

  condition:
    any of them
}