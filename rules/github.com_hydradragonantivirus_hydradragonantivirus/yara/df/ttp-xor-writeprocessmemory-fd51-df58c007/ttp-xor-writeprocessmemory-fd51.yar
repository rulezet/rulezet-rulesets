rule TTP_XOR_WriteProcessMemory_fd51 {
  strings:
    $key_fd51 = { aa 23 [2] 98 01 [2] 9e 34 [2] b0 34 [2] 8f 28 }

  condition:
    any of them
}