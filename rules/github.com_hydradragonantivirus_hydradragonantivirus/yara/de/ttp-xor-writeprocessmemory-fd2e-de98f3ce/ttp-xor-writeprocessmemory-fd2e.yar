rule TTP_XOR_WriteProcessMemory_fd2e {
  strings:
    $key_fd2e = { aa 5c [2] 98 7e [2] 9e 4b [2] b0 4b [2] 8f 57 }

  condition:
    any of them
}