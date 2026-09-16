rule TTP_XOR_WriteProcessMemory_034d {
  strings:
    $key_034d = { 54 3f [2] 66 1d [2] 60 28 [2] 4e 28 [2] 71 34 }

  condition:
    any of them
}