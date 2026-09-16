rule TTP_XOR_WriteProcessMemory_6785 {
  strings:
    $key_6785 = { 30 f7 [2] 02 d5 [2] 04 e0 [2] 2a e0 [2] 15 fc }

  condition:
    any of them
}