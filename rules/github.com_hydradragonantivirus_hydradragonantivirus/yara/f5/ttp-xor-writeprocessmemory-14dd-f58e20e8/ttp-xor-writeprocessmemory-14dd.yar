rule TTP_XOR_WriteProcessMemory_14dd {
  strings:
    $key_14dd = { 43 af [2] 71 8d [2] 77 b8 [2] 59 b8 [2] 66 a4 }

  condition:
    any of them
}