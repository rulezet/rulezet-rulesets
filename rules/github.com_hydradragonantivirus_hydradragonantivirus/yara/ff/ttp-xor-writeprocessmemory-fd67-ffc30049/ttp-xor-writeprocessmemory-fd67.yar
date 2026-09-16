rule TTP_XOR_WriteProcessMemory_fd67 {
  strings:
    $key_fd67 = { aa 15 [2] 98 37 [2] 9e 02 [2] b0 02 [2] 8f 1e }

  condition:
    any of them
}