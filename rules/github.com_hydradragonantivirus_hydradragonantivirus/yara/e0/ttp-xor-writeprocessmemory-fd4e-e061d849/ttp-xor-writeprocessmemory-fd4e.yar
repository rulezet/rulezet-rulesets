rule TTP_XOR_WriteProcessMemory_fd4e {
  strings:
    $key_fd4e = { aa 3c [2] 98 1e [2] 9e 2b [2] b0 2b [2] 8f 37 }

  condition:
    any of them
}