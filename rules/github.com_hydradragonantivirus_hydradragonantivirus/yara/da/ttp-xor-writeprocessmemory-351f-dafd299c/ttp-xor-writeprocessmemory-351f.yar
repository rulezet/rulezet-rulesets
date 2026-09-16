rule TTP_XOR_WriteProcessMemory_351f {
  strings:
    $key_351f = { 62 6d [2] 50 4f [2] 56 7a [2] 78 7a [2] 47 66 }

  condition:
    any of them
}