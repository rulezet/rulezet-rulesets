rule TTP_XOR_WriteProcessMemory_fd44 {
  strings:
    $key_fd44 = { aa 36 [2] 98 14 [2] 9e 21 [2] b0 21 [2] 8f 3d }

  condition:
    any of them
}