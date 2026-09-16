rule TTP_XOR_WriteProcessMemory_315f {
  strings:
    $key_315f = { 66 2d [2] 54 0f [2] 52 3a [2] 7c 3a [2] 43 26 }

  condition:
    any of them
}