rule TTP_XOR_WriteProcessMemory_913f {
  strings:
    $key_913f = { c6 4d [2] f4 6f [2] f2 5a [2] dc 5a [2] e3 46 }

  condition:
    any of them
}