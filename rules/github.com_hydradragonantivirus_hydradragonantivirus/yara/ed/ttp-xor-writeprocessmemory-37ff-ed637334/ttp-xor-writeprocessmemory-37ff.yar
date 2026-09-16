rule TTP_XOR_WriteProcessMemory_37ff {
  strings:
    $key_37ff = { 60 8d [2] 52 af [2] 54 9a [2] 7a 9a [2] 45 86 }

  condition:
    any of them
}