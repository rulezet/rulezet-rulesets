rule TTP_XOR_WriteProcessMemory_3338 {
  strings:
    $key_3338 = { 64 4a [2] 56 68 [2] 50 5d [2] 7e 5d [2] 41 41 }

  condition:
    any of them
}