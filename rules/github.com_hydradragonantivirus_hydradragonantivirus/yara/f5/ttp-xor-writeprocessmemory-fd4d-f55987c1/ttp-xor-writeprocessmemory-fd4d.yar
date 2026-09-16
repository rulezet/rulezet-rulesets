rule TTP_XOR_WriteProcessMemory_fd4d {
  strings:
    $key_fd4d = { aa 3f [2] 98 1d [2] 9e 28 [2] b0 28 [2] 8f 34 }

  condition:
    any of them
}