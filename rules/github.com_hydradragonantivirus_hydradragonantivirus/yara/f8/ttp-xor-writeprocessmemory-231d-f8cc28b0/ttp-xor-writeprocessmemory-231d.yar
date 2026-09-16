rule TTP_XOR_WriteProcessMemory_231d {
  strings:
    $key_231d = { 74 6f [2] 46 4d [2] 40 78 [2] 6e 78 [2] 51 64 }

  condition:
    any of them
}