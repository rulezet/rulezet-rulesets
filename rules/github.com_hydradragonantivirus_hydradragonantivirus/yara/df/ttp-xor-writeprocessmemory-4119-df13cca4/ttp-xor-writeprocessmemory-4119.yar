rule TTP_XOR_WriteProcessMemory_4119 {
  strings:
    $key_4119 = { 16 6b [2] 24 49 [2] 22 7c [2] 0c 7c [2] 33 60 }

  condition:
    any of them
}