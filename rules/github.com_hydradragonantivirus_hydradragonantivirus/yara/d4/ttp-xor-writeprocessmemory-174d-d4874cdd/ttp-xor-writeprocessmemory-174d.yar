rule TTP_XOR_WriteProcessMemory_174d {
  strings:
    $key_174d = { 40 3f [2] 72 1d [2] 74 28 [2] 5a 28 [2] 65 34 }

  condition:
    any of them
}