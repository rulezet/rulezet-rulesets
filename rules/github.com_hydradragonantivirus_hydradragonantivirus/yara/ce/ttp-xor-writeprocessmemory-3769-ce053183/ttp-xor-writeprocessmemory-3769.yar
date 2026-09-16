rule TTP_XOR_WriteProcessMemory_3769 {
  strings:
    $key_3769 = { 60 1b [2] 52 39 [2] 54 0c [2] 7a 0c [2] 45 10 }

  condition:
    any of them
}