rule TTP_XOR_WriteProcessMemory_225d {
  strings:
    $key_225d = { 75 2f [2] 47 0d [2] 41 38 [2] 6f 38 [2] 50 24 }

  condition:
    any of them
}