rule TTP_XOR_WriteProcessMemory_382d {
  strings:
    $key_382d = { 6f 5f [2] 5d 7d [2] 5b 48 [2] 75 48 [2] 4a 54 }

  condition:
    any of them
}