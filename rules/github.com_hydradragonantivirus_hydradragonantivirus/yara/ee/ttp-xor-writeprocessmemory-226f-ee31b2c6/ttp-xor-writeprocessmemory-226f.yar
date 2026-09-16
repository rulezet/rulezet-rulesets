rule TTP_XOR_WriteProcessMemory_226f {
  strings:
    $key_226f = { 75 1d [2] 47 3f [2] 41 0a [2] 6f 0a [2] 50 16 }

  condition:
    any of them
}