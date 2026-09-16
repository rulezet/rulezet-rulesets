rule TTP_XOR_WriteProcessMemory_13dd {
  strings:
    $key_13dd = { 44 af [2] 76 8d [2] 70 b8 [2] 5e b8 [2] 61 a4 }

  condition:
    any of them
}