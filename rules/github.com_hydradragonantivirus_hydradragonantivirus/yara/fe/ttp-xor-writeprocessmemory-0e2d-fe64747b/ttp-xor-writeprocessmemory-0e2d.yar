rule TTP_XOR_WriteProcessMemory_0e2d {
  strings:
    $key_0e2d = { 59 5f [2] 6b 7d [2] 6d 48 [2] 43 48 [2] 7c 54 }

  condition:
    any of them
}