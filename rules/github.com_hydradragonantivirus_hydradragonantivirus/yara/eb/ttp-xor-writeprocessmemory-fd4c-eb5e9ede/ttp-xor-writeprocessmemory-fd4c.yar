rule TTP_XOR_WriteProcessMemory_fd4c {
  strings:
    $key_fd4c = { aa 3e [2] 98 1c [2] 9e 29 [2] b0 29 [2] 8f 35 }

  condition:
    any of them
}