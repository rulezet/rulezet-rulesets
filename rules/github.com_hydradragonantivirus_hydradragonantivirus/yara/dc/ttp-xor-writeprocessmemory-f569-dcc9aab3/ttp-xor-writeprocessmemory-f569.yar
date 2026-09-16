rule TTP_XOR_WriteProcessMemory_f569 {
  strings:
    $key_f569 = { a2 1b [2] 90 39 [2] 96 0c [2] b8 0c [2] 87 10 }

  condition:
    any of them
}