rule TTP_XOR_WriteProcessMemory_addd {
  strings:
    $key_addd = { fa af [2] c8 8d [2] ce b8 [2] e0 b8 [2] df a4 }

  condition:
    any of them
}