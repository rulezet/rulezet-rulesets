rule TTP_XOR_WriteProcessMemory_1218 {
  strings:
    $key_1218 = { 45 6a [2] 77 48 [2] 71 7d [2] 5f 7d [2] 60 61 }

  condition:
    any of them
}