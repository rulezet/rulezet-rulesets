rule TTP_XOR_WriteProcessMemory_2a5d {
  strings:
    $key_2a5d = { 7d 2f [2] 4f 0d [2] 49 38 [2] 67 38 [2] 58 24 }

  condition:
    any of them
}