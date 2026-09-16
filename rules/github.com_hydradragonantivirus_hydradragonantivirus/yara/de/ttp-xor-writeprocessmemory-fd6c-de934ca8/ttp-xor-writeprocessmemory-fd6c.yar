rule TTP_XOR_WriteProcessMemory_fd6c {
  strings:
    $key_fd6c = { aa 1e [2] 98 3c [2] 9e 09 [2] b0 09 [2] 8f 15 }

  condition:
    any of them
}