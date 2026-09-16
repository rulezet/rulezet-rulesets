rule TTP_XOR_WriteProcessMemory_3285 {
  strings:
    $key_3285 = { 65 f7 [2] 57 d5 [2] 51 e0 [2] 7f e0 [2] 40 fc }

  condition:
    any of them
}