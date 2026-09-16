rule TTP_XOR_WriteProcessMemory_eed3 {
  strings:
    $key_eed3 = { b9 a1 [2] 8b 83 [2] 8d b6 [2] a3 b6 [2] 9c aa }

  condition:
    any of them
}