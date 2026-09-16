rule TTP_XOR_WriteProcessMemory_11ff {
  strings:
    $key_11ff = { 46 8d [2] 74 af [2] 72 9a [2] 5c 9a [2] 63 86 }

  condition:
    any of them
}