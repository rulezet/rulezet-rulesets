rule TTP_XOR_WriteProcessMemory_fd65 {
  strings:
    $key_fd65 = { aa 17 [2] 98 35 [2] 9e 00 [2] b0 00 [2] 8f 1c }

  condition:
    any of them
}