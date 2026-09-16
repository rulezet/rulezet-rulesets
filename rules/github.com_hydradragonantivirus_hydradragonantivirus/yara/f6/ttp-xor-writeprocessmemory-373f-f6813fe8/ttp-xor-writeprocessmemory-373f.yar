rule TTP_XOR_WriteProcessMemory_373f {
  strings:
    $key_373f = { 60 4d [2] 52 6f [2] 54 5a [2] 7a 5a [2] 45 46 }

  condition:
    any of them
}