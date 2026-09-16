rule TTP_XOR_WriteProcessMemory_91fe {
  strings:
    $key_91fe = { c6 8c [2] f4 ae [2] f2 9b [2] dc 9b [2] e3 87 }

  condition:
    any of them
}