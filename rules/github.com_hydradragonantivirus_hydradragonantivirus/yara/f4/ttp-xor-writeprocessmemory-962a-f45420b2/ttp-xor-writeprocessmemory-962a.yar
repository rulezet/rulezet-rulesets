rule TTP_XOR_WriteProcessMemory_962a {
  strings:
    $key_962a = { c1 58 [2] f3 7a [2] f5 4f [2] db 4f [2] e4 53 }

  condition:
    any of them
}