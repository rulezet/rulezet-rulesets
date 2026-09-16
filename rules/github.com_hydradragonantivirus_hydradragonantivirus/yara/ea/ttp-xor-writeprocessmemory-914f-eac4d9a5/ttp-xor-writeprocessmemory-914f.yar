rule TTP_XOR_WriteProcessMemory_914f {
  strings:
    $key_914f = { c6 3d [2] f4 1f [2] f2 2a [2] dc 2a [2] e3 36 }

  condition:
    any of them
}