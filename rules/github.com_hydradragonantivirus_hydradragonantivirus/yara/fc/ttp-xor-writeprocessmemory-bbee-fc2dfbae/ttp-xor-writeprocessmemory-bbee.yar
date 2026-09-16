rule TTP_XOR_WriteProcessMemory_bbee {
  strings:
    $key_bbee = { ec 9c [2] de be [2] d8 8b [2] f6 8b [2] c9 97 }

  condition:
    any of them
}