rule TTP_XOR_WriteProcessMemory_4146 {
  strings:
    $key_4146 = { 16 34 [2] 24 16 [2] 22 23 [2] 0c 23 [2] 33 3f }

  condition:
    any of them
}