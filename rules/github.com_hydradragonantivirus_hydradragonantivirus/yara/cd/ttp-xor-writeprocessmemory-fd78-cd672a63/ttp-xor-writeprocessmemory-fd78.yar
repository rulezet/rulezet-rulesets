rule TTP_XOR_WriteProcessMemory_fd78 {
  strings:
    $key_fd78 = { aa 0a [2] 98 28 [2] 9e 1d [2] b0 1d [2] 8f 01 }

  condition:
    any of them
}