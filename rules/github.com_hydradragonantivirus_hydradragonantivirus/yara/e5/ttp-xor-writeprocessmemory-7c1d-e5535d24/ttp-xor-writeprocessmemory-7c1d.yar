rule TTP_XOR_WriteProcessMemory_7c1d {
  strings:
    $key_7c1d = { 2b 6f [2] 19 4d [2] 1f 78 [2] 31 78 [2] 0e 64 }

  condition:
    any of them
}