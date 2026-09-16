rule TTP_XOR_WriteProcessMemory_802a {
  strings:
    $key_802a = { d7 58 [2] e5 7a [2] e3 4f [2] cd 4f [2] f2 53 }

  condition:
    any of them
}