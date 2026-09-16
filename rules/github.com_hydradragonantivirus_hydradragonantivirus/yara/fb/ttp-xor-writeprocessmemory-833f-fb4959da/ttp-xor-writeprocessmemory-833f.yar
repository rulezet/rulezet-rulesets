rule TTP_XOR_WriteProcessMemory_833f {
  strings:
    $key_833f = { d4 4d [2] e6 6f [2] e0 5a [2] ce 5a [2] f1 46 }

  condition:
    any of them
}