rule TTP_XOR_WriteProcessMemory_817d {
  strings:
    $key_817d = { d6 0f [2] e4 2d [2] e2 18 [2] cc 18 [2] f3 04 }

  condition:
    any of them
}