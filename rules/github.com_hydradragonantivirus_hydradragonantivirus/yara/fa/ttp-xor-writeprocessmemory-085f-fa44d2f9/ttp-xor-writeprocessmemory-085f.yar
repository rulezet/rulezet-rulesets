rule TTP_XOR_WriteProcessMemory_085f {
  strings:
    $key_085f = { 5f 2d [2] 6d 0f [2] 6b 3a [2] 45 3a [2] 7a 26 }

  condition:
    any of them
}