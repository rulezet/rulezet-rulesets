rule TTP_XOR_WriteProcessMemory_863e {
  strings:
    $key_863e = { d1 4c [2] e3 6e [2] e5 5b [2] cb 5b [2] f4 47 }

  condition:
    any of them
}