rule TTP_XOR_WriteProcessMemory_834f {
  strings:
    $key_834f = { d4 3d [2] e6 1f [2] e0 2a [2] ce 2a [2] f1 36 }

  condition:
    any of them
}