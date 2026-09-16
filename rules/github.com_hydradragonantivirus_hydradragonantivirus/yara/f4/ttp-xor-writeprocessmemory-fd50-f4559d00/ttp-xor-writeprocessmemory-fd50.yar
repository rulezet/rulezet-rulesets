rule TTP_XOR_WriteProcessMemory_fd50 {
  strings:
    $key_fd50 = { aa 22 [2] 98 00 [2] 9e 35 [2] b0 35 [2] 8f 29 }

  condition:
    any of them
}