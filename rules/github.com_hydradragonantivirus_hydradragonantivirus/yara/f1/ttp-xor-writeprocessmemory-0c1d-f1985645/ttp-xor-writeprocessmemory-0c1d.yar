rule TTP_XOR_WriteProcessMemory_0c1d {
  strings:
    $key_0c1d = { 5b 6f [2] 69 4d [2] 6f 78 [2] 41 78 [2] 7e 64 }

  condition:
    any of them
}