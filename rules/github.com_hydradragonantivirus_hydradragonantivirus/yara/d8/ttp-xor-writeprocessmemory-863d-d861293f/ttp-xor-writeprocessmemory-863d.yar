rule TTP_XOR_WriteProcessMemory_863d {
  strings:
    $key_863d = { d1 4f [2] e3 6d [2] e5 58 [2] cb 58 [2] f4 44 }

  condition:
    any of them
}