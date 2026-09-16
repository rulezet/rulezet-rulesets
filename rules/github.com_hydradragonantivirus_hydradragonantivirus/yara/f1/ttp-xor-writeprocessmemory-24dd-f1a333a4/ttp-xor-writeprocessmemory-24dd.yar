rule TTP_XOR_WriteProcessMemory_24dd {
  strings:
    $key_24dd = { 73 af [2] 41 8d [2] 47 b8 [2] 69 b8 [2] 56 a4 }

  condition:
    any of them
}