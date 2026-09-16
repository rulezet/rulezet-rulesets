rule TTP_XOR_WriteProcessMemory_415d {
  strings:
    $key_415d = { 16 2f [2] 24 0d [2] 22 38 [2] 0c 38 [2] 33 24 }

  condition:
    any of them
}