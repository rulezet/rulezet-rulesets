rule TTP_XOR_WriteProcessMemory_451d {
  strings:
    $key_451d = { 12 6f [2] 20 4d [2] 26 78 [2] 08 78 [2] 37 64 }

  condition:
    any of them
}