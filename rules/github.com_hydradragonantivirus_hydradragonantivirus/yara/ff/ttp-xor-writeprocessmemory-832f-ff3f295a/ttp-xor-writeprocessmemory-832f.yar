rule TTP_XOR_WriteProcessMemory_832f {
  strings:
    $key_832f = { d4 5d [2] e6 7f [2] e0 4a [2] ce 4a [2] f1 56 }

  condition:
    any of them
}