rule TTP_XOR_WriteProcessMemory_0508 {
  strings:
    $key_0508 = { 52 7a [2] 60 58 [2] 66 6d [2] 48 6d [2] 77 71 }

  condition:
    any of them
}