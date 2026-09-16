rule TTP_XOR_WriteProcessMemory_5419 {
  strings:
    $key_5419 = { 03 6b [2] 31 49 [2] 37 7c [2] 19 7c [2] 26 60 }

  condition:
    any of them
}