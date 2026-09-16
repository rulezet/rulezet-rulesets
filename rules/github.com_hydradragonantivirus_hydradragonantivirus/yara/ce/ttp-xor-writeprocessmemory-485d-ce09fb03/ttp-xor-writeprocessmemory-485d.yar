rule TTP_XOR_WriteProcessMemory_485d {
  strings:
    $key_485d = { 1f 2f [2] 2d 0d [2] 2b 38 [2] 05 38 [2] 3a 24 }

  condition:
    any of them
}