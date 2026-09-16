rule TTP_XOR_WriteProcessMemory_fd13 {
  strings:
    $key_fd13 = { aa 61 [2] 98 43 [2] 9e 76 [2] b0 76 [2] 8f 6a }

  condition:
    any of them
}