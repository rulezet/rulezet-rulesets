rule TTP_XOR_WriteProcessMemory_fd68 {
  strings:
    $key_fd68 = { aa 1a [2] 98 38 [2] 9e 0d [2] b0 0d [2] 8f 11 }

  condition:
    any of them
}