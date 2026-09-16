rule TTP_XOR_WriteProcessMemory_fd33 {
  strings:
    $key_fd33 = { aa 41 [2] 98 63 [2] 9e 56 [2] b0 56 [2] 8f 4a }

  condition:
    any of them
}