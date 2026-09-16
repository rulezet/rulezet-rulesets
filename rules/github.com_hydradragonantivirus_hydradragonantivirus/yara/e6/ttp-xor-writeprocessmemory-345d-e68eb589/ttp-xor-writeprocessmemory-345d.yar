rule TTP_XOR_WriteProcessMemory_345d {
  strings:
    $key_345d = { 63 2f [2] 51 0d [2] 57 38 [2] 79 38 [2] 46 24 }

  condition:
    any of them
}