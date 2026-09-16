rule TTP_XOR_WriteProcessMemory_fd62 {
  strings:
    $key_fd62 = { aa 10 [2] 98 32 [2] 9e 07 [2] b0 07 [2] 8f 1b }

  condition:
    any of them
}