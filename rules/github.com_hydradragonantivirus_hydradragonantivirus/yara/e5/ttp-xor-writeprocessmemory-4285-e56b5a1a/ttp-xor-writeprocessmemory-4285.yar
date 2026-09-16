rule TTP_XOR_WriteProcessMemory_4285 {
  strings:
    $key_4285 = { 15 f7 [2] 27 d5 [2] 21 e0 [2] 0f e0 [2] 30 fc }

  condition:
    any of them
}