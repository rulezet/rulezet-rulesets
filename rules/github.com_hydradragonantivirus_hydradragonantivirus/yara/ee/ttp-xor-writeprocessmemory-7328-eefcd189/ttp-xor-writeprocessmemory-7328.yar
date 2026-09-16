rule TTP_XOR_WriteProcessMemory_7328 {
  strings:
    $key_7328 = { 24 5a [2] 16 78 [2] 10 4d [2] 3e 4d [2] 01 51 }

  condition:
    any of them
}