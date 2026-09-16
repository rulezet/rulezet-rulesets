rule TTP_XOR_WriteProcessMemory_3c1d {
  strings:
    $key_3c1d = { 6b 6f [2] 59 4d [2] 5f 78 [2] 71 78 [2] 4e 64 }

  condition:
    any of them
}