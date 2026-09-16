rule TTP_XOR_WriteProcessMemory_f966 {
  strings:
    $key_f966 = { ae 14 [2] 9c 36 [2] 9a 03 [2] b4 03 [2] 8b 1f }

  condition:
    any of them
}