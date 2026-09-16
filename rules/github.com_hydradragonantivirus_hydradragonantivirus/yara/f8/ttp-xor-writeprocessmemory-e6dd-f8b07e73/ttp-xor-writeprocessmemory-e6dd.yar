rule TTP_XOR_WriteProcessMemory_e6dd {
  strings:
    $key_e6dd = { b1 af [2] 83 8d [2] 85 b8 [2] ab b8 [2] 94 a4 }

  condition:
    any of them
}