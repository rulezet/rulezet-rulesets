rule TTP_XOR_WriteProcessMemory_c569 {
  strings:
    $key_c569 = { 92 1b [2] a0 39 [2] a6 0c [2] 88 0c [2] b7 10 }

  condition:
    any of them
}