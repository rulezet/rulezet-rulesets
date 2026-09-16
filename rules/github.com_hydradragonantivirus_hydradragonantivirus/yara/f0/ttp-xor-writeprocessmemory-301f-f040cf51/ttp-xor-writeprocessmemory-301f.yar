rule TTP_XOR_WriteProcessMemory_301f {
  strings:
    $key_301f = { 67 6d [2] 55 4f [2] 53 7a [2] 7d 7a [2] 42 66 }

  condition:
    any of them
}