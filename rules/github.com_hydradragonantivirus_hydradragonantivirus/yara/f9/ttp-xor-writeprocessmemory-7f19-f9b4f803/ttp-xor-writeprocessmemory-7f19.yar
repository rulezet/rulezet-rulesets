rule TTP_XOR_WriteProcessMemory_7f19 {
  strings:
    $key_7f19 = { 28 6b [2] 1a 49 [2] 1c 7c [2] 32 7c [2] 0d 60 }

  condition:
    any of them
}