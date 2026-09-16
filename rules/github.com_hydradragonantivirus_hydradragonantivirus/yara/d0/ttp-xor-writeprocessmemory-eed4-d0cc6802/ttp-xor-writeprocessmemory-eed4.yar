rule TTP_XOR_WriteProcessMemory_eed4 {
  strings:
    $key_eed4 = { b9 a6 [2] 8b 84 [2] 8d b1 [2] a3 b1 [2] 9c ad }

  condition:
    any of them
}