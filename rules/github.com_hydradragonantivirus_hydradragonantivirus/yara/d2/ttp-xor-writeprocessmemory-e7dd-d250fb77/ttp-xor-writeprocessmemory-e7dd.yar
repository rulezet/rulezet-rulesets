rule TTP_XOR_WriteProcessMemory_e7dd {
  strings:
    $key_e7dd = { b0 af [2] 82 8d [2] 84 b8 [2] aa b8 [2] 95 a4 }

  condition:
    any of them
}