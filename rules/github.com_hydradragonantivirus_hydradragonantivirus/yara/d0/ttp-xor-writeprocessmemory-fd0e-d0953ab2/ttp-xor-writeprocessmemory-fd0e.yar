rule TTP_XOR_WriteProcessMemory_fd0e {
  strings:
    $key_fd0e = { aa 7c [2] 98 5e [2] 9e 6b [2] b0 6b [2] 8f 77 }

  condition:
    any of them
}