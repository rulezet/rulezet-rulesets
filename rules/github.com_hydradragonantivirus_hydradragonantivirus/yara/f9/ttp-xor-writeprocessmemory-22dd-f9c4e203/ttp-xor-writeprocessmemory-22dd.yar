rule TTP_XOR_WriteProcessMemory_22dd {
  strings:
    $key_22dd = { 75 af [2] 47 8d [2] 41 b8 [2] 6f b8 [2] 50 a4 }

  condition:
    any of them
}