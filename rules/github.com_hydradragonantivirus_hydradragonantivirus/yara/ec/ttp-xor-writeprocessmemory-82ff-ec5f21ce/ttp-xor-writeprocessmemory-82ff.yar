rule TTP_XOR_WriteProcessMemory_82ff {
  strings:
    $key_82ff = { d5 8d [2] e7 af [2] e1 9a [2] cf 9a [2] f0 86 }

  condition:
    any of them
}