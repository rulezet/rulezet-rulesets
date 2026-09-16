rule TTP_XOR_WriteProcessMemory_284d {
  strings:
    $key_284d = { 7f 3f [2] 4d 1d [2] 4b 28 [2] 65 28 [2] 5a 34 }

  condition:
    any of them
}