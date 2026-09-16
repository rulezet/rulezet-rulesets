rule TTP_XOR_WriteProcessMemory_0569 {
  strings:
    $key_0569 = { 52 1b [2] 60 39 [2] 66 0c [2] 48 0c [2] 77 10 }

  condition:
    any of them
}