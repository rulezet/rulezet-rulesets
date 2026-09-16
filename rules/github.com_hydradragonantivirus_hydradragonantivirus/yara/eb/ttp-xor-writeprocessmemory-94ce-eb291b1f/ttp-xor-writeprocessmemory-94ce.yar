rule TTP_XOR_WriteProcessMemory_94ce {
  strings:
    $key_94ce = { c3 bc [2] f1 9e [2] f7 ab [2] d9 ab [2] e6 b7 }

  condition:
    any of them
}