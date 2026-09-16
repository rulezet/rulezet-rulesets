rule TTP_XOR_WriteProcessMemory_145f {
  strings:
    $key_145f = { 43 2d [2] 71 0f [2] 77 3a [2] 59 3a [2] 66 26 }

  condition:
    any of them
}