rule TTP_XOR_WriteProcessMemory_91ff {
  strings:
    $key_91ff = { c6 8d [2] f4 af [2] f2 9a [2] dc 9a [2] e3 86 }

  condition:
    any of them
}