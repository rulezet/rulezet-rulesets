rule TTP_XOR_WriteProcessMemory_4219 {
  strings:
    $key_4219 = { 15 6b [2] 27 49 [2] 21 7c [2] 0f 7c [2] 30 60 }

  condition:
    any of them
}