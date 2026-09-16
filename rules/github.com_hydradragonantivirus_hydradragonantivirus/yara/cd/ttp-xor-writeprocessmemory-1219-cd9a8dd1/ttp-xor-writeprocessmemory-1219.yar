rule TTP_XOR_WriteProcessMemory_1219 {
  strings:
    $key_1219 = { 45 6b [2] 77 49 [2] 71 7c [2] 5f 7c [2] 60 60 }

  condition:
    any of them
}