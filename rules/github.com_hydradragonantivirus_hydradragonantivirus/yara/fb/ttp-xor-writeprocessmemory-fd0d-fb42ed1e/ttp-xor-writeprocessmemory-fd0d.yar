rule TTP_XOR_WriteProcessMemory_fd0d {
  strings:
    $key_fd0d = { aa 7f [2] 98 5d [2] 9e 68 [2] b0 68 [2] 8f 74 }

  condition:
    any of them
}