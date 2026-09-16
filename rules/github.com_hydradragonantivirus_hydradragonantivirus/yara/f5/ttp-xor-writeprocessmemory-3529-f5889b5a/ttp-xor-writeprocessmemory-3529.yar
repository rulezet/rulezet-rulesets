rule TTP_XOR_WriteProcessMemory_3529 {
  strings:
    $key_3529 = { 62 5b [2] 50 79 [2] 56 4c [2] 78 4c [2] 47 50 }

  condition:
    any of them
}