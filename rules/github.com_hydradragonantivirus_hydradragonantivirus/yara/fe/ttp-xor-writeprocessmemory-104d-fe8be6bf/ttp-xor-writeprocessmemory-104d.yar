rule TTP_XOR_WriteProcessMemory_104d {
  strings:
    $key_104d = { 47 3f [2] 75 1d [2] 73 28 [2] 5d 28 [2] 62 34 }

  condition:
    any of them
}