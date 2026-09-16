rule TTP_XOR_WriteProcessMemory_863f {
  strings:
    $key_863f = { d1 4d [2] e3 6f [2] e5 5a [2] cb 5a [2] f4 46 }

  condition:
    any of them
}