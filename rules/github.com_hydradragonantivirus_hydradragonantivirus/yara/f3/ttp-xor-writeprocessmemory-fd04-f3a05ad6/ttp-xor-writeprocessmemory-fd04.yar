rule TTP_XOR_WriteProcessMemory_fd04 {
  strings:
    $key_fd04 = { aa 76 [2] 98 54 [2] 9e 61 [2] b0 61 [2] 8f 7d }

  condition:
    any of them
}