rule TTP_XOR_WriteProcessMemory_74ff {
  strings:
    $key_74ff = { 23 8d [2] 11 af [2] 17 9a [2] 39 9a [2] 06 86 }

  condition:
    any of them
}