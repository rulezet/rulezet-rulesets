rule TTP_XOR_WriteProcessMemory_90dd {
  strings:
    $key_90dd = { c7 af [2] f5 8d [2] f3 b8 [2] dd b8 [2] e2 a4 }

  condition:
    any of them
}