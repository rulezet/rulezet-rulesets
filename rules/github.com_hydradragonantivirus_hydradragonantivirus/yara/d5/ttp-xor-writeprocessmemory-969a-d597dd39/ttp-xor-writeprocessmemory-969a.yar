rule TTP_XOR_WriteProcessMemory_969a {
  strings:
    $key_969a = { c1 e8 [2] f3 ca [2] f5 ff [2] db ff [2] e4 e3 }

  condition:
    any of them
}