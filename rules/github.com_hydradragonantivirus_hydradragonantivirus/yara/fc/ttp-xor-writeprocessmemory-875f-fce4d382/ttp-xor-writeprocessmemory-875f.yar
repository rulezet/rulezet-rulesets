rule TTP_XOR_WriteProcessMemory_875f {
  strings:
    $key_875f = { d0 2d [2] e2 0f [2] e4 3a [2] ca 3a [2] f5 26 }

  condition:
    any of them
}