rule TTP_XOR_WriteProcessMemory_fd37 {
  strings:
    $key_fd37 = { aa 45 [2] 98 67 [2] 9e 52 [2] b0 52 [2] 8f 4e }

  condition:
    any of them
}