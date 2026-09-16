rule TTP_XOR_WriteProcessMemory_802f {
  strings:
    $key_802f = { d7 5d [2] e5 7f [2] e3 4a [2] cd 4a [2] f2 56 }

  condition:
    any of them
}