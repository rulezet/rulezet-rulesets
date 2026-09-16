rule TTP_XOR_WriteProcessMemory_34dd {
  strings:
    $key_34dd = { 63 af [2] 51 8d [2] 57 b8 [2] 79 b8 [2] 46 a4 }

  condition:
    any of them
}