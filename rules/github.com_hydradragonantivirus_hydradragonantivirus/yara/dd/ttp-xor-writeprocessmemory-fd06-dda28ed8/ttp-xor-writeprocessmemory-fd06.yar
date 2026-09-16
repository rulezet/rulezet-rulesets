rule TTP_XOR_WriteProcessMemory_fd06 {
  strings:
    $key_fd06 = { aa 74 [2] 98 56 [2] 9e 63 [2] b0 63 [2] 8f 7f }

  condition:
    any of them
}