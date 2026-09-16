rule TTP_XOR_WriteProcessMemory_070f {
  strings:
    $key_070f = { 50 7d [2] 62 5f [2] 64 6a [2] 4a 6a [2] 75 76 }

  condition:
    any of them
}