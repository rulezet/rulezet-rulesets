rule TTP_XOR_WriteProcessMemory_2d36 {
  strings:
    $key_2d36 = { 7a 44 [2] 48 66 [2] 4e 53 [2] 60 53 [2] 5f 4f }

  condition:
    any of them
}