rule TTP_XOR_WriteProcessMemory_fd32 {
  strings:
    $key_fd32 = { aa 40 [2] 98 62 [2] 9e 57 [2] b0 57 [2] 8f 4b }

  condition:
    any of them
}