rule TTP_XOR_WriteProcessMemory_911f {
  strings:
    $key_911f = { c6 6d [2] f4 4f [2] f2 7a [2] dc 7a [2] e3 66 }

  condition:
    any of them
}