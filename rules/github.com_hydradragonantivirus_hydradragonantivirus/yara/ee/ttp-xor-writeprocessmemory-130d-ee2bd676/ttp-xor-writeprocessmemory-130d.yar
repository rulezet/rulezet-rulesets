rule TTP_XOR_WriteProcessMemory_130d {
  strings:
    $key_130d = { 44 7f [2] 76 5d [2] 70 68 [2] 5e 68 [2] 61 74 }

  condition:
    any of them
}