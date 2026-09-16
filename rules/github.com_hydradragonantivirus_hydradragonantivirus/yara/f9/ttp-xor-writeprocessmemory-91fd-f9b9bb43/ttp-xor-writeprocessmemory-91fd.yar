rule TTP_XOR_WriteProcessMemory_91fd {
  strings:
    $key_91fd = { c6 8f [2] f4 ad [2] f2 98 [2] dc 98 [2] e3 84 }

  condition:
    any of them
}