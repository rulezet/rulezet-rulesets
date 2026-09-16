rule TTP_XOR_WriteProcessMemory_281d {
  strings:
    $key_281d = { 7f 6f [2] 4d 4d [2] 4b 78 [2] 65 78 [2] 5a 64 }

  condition:
    any of them
}