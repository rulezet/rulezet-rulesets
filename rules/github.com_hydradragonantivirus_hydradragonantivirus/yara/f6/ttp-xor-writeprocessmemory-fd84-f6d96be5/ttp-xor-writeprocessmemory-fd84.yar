rule TTP_XOR_WriteProcessMemory_fd84 {
  strings:
    $key_fd84 = { aa f6 [2] 98 d4 [2] 9e e1 [2] b0 e1 [2] 8f fd }

  condition:
    any of them
}