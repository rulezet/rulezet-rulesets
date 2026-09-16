rule TTP_XOR_WriteProcessMemory_03ff {
  strings:
    $key_03ff = { 54 8d [2] 66 af [2] 60 9a [2] 4e 9a [2] 71 86 }

  condition:
    any of them
}