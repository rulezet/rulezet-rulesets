rule TTP_XOR_WriteProcessMemory_014d {
  strings:
    $key_014d = { 56 3f [2] 64 1d [2] 62 28 [2] 4c 28 [2] 73 34 }

  condition:
    any of them
}