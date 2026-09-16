rule TTP_XOR_WriteProcessMemory_8319 {
  strings:
    $key_8319 = { d4 6b [2] e6 49 [2] e0 7c [2] ce 7c [2] f1 60 }

  condition:
    any of them
}