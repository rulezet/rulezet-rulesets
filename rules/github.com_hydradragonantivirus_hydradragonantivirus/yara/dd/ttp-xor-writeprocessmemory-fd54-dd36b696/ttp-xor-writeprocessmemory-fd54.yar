rule TTP_XOR_WriteProcessMemory_fd54 {
  strings:
    $key_fd54 = { aa 26 [2] 98 04 [2] 9e 31 [2] b0 31 [2] 8f 2d }

  condition:
    any of them
}