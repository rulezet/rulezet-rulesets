rule TTP_XOR_WriteProcessMemory_fd42 {
  strings:
    $key_fd42 = { aa 30 [2] 98 12 [2] 9e 27 [2] b0 27 [2] 8f 3b }

  condition:
    any of them
}