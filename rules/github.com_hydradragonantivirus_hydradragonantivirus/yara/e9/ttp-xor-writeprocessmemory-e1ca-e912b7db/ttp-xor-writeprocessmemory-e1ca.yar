rule TTP_XOR_WriteProcessMemory_e1ca {
  strings:
    $key_e1ca = { b6 b8 [2] 84 9a [2] 82 af [2] ac af [2] 93 b3 }

  condition:
    any of them
}