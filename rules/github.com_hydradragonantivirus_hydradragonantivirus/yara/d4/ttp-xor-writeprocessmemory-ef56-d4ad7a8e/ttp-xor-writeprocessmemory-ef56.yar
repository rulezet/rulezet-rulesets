rule TTP_XOR_WriteProcessMemory_ef56 {
  strings:
    $key_ef56 = { b8 24 [2] 8a 06 [2] 8c 33 [2] a2 33 [2] 9d 2f }

  condition:
    any of them
}