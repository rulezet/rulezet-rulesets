rule TTP_XOR_WriteProcessMemory_0019 {
  strings:
    $key_0019 = { 57 6b [2] 65 49 [2] 63 7c [2] 4d 7c [2] 72 60 }

  condition:
    any of them
}