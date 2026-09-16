rule TTP_XOR_WriteProcessMemory_1228 {
  strings:
    $key_1228 = { 45 5a [2] 77 78 [2] 71 4d [2] 5f 4d [2] 60 51 }

  condition:
    any of them
}