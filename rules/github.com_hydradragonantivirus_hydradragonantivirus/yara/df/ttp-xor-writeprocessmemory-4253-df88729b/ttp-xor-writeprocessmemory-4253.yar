rule TTP_XOR_WriteProcessMemory_4253 {
  strings:
    $key_4253 = { 15 21 [2] 27 03 [2] 21 36 [2] 0f 36 [2] 30 2a }

  condition:
    any of them
}