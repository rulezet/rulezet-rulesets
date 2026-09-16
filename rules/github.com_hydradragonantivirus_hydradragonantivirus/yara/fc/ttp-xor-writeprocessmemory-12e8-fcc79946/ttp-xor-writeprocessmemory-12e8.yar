rule TTP_XOR_WriteProcessMemory_12e8 {
  strings:
    $key_12e8 = { 45 9a [2] 77 b8 [2] 71 8d [2] 5f 8d [2] 60 91 }

  condition:
    any of them
}