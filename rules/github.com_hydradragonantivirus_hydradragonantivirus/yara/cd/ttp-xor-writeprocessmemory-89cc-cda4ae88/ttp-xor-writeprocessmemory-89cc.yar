rule TTP_XOR_WriteProcessMemory_89cc {
  strings:
    $key_89cc = { de be [2] ec 9c [2] ea a9 [2] c4 a9 [2] fb b5 }

  condition:
    any of them
}