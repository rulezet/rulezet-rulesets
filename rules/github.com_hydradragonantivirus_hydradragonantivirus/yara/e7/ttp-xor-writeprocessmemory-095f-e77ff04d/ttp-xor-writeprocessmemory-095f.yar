rule TTP_XOR_WriteProcessMemory_095f {
  strings:
    $key_095f = { 5e 2d [2] 6c 0f [2] 6a 3a [2] 44 3a [2] 7b 26 }

  condition:
    any of them
}