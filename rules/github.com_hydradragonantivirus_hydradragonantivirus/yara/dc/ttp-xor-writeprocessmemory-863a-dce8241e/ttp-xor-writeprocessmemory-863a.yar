rule TTP_XOR_WriteProcessMemory_863a {
  strings:
    $key_863a = { d1 48 [2] e3 6a [2] e5 5f [2] cb 5f [2] f4 43 }

  condition:
    any of them
}