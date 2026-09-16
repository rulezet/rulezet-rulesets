rule TTP_XOR_WriteProcessMemory_fd5a {
  strings:
    $key_fd5a = { aa 28 [2] 98 0a [2] 9e 3f [2] b0 3f [2] 8f 23 }

  condition:
    any of them
}