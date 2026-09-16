rule TTP_XOR_WriteProcessMemory_e85f {
  strings:
    $key_e85f = { bf 2d [2] 8d 0f [2] 8b 3a [2] a5 3a [2] 9a 26 }

  condition:
    any of them
}