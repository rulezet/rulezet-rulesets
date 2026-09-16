rule TTP_XOR_WriteProcessMemory_fd15 {
  strings:
    $key_fd15 = { aa 67 [2] 98 45 [2] 9e 70 [2] b0 70 [2] 8f 6c }

  condition:
    any of them
}