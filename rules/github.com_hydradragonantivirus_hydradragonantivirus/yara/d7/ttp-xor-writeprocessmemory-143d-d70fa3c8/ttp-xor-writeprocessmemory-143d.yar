rule TTP_XOR_WriteProcessMemory_143d {
  strings:
    $key_143d = { 43 4f [2] 71 6d [2] 77 58 [2] 59 58 [2] 66 44 }

  condition:
    any of them
}