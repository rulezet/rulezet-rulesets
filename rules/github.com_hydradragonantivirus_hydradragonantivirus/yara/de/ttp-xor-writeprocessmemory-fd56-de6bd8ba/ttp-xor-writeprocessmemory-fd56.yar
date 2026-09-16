rule TTP_XOR_WriteProcessMemory_fd56 {
  strings:
    $key_fd56 = { aa 24 [2] 98 06 [2] 9e 33 [2] b0 33 [2] 8f 2f }

  condition:
    any of them
}