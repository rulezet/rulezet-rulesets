rule TTP_XOR_WriteProcessMemory_2fb2 {
  strings:
    $key_2fb2 = { 78 c0 [2] 4a e2 [2] 4c d7 [2] 62 d7 [2] 5d cb }

  condition:
    any of them
}