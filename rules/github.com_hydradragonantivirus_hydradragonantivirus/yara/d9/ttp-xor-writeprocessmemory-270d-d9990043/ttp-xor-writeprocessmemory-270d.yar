rule TTP_XOR_WriteProcessMemory_270d {
  strings:
    $key_270d = { 70 7f [2] 42 5d [2] 44 68 [2] 6a 68 [2] 55 74 }

  condition:
    any of them
}