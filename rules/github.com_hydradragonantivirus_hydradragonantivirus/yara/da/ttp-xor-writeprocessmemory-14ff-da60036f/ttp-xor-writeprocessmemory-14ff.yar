rule TTP_XOR_WriteProcessMemory_14ff {
  strings:
    $key_14ff = { 43 8d [2] 71 af [2] 77 9a [2] 59 9a [2] 66 86 }

  condition:
    any of them
}