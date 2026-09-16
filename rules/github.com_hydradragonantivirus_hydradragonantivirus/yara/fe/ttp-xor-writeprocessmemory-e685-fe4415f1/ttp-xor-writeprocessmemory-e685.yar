rule TTP_XOR_WriteProcessMemory_e685 {
  strings:
    $key_e685 = { b1 f7 [2] 83 d5 [2] 85 e0 [2] ab e0 [2] 94 fc }

  condition:
    any of them
}