rule TTP_XOR_WriteProcessMemory_144a {
  strings:
    $key_144a = { 43 38 [2] 71 1a [2] 77 2f [2] 59 2f [2] 66 33 }

  condition:
    any of them
}