rule TTP_XOR_WriteProcessMemory_fd26 {
  strings:
    $key_fd26 = { aa 54 [2] 98 76 [2] 9e 43 [2] b0 43 [2] 8f 5f }

  condition:
    any of them
}