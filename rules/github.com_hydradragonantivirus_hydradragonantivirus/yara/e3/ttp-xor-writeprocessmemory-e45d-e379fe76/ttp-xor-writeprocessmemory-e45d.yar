rule TTP_XOR_WriteProcessMemory_e45d {
  strings:
    $key_e45d = { b3 2f [2] 81 0d [2] 87 38 [2] a9 38 [2] 96 24 }

  condition:
    any of them
}