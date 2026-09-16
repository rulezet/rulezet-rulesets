rule TTP_XOR_WriteProcessMemory_fd11 {
  strings:
    $key_fd11 = { aa 63 [2] 98 41 [2] 9e 74 [2] b0 74 [2] 8f 68 }

  condition:
    any of them
}