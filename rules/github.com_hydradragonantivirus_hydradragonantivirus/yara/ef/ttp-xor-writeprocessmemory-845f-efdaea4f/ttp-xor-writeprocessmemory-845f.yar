rule TTP_XOR_WriteProcessMemory_845f {
  strings:
    $key_845f = { d3 2d [2] e1 0f [2] e7 3a [2] c9 3a [2] f6 26 }

  condition:
    any of them
}