rule TTP_XOR_WriteProcessMemory_56ca {
  strings:
    $key_56ca = { 01 b8 [2] 33 9a [2] 35 af [2] 1b af [2] 24 b3 }

  condition:
    any of them
}