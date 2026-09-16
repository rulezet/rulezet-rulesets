rule TTP_XOR_WriteProcessMemory_fd57 {
  strings:
    $key_fd57 = { aa 25 [2] 98 07 [2] 9e 32 [2] b0 32 [2] 8f 2e }

  condition:
    any of them
}