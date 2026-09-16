rule TTP_XOR_WriteProcessMemory_0f61 {
  strings:
    $key_0f61 = { 58 13 [2] 6a 31 [2] 6c 04 [2] 42 04 [2] 7d 18 }

  condition:
    any of them
}