rule TTP_XOR_WriteProcessMemory_fd09 {
  strings:
    $key_fd09 = { aa 7b [2] 98 59 [2] 9e 6c [2] b0 6c [2] 8f 70 }

  condition:
    any of them
}