rule TTP_XOR_WriteProcessMemory_732d {
  strings:
    $key_732d = { 24 5f [2] 16 7d [2] 10 48 [2] 3e 48 [2] 01 54 }

  condition:
    any of them
}