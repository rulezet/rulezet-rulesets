rule TTP_XOR_WriteProcessMemory_950a {
  strings:
    $key_950a = { c2 78 [2] f0 5a [2] f6 6f [2] d8 6f [2] e7 73 }

  condition:
    any of them
}