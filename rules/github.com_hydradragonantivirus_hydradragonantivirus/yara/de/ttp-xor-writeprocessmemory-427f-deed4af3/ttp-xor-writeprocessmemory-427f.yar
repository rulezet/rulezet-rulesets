rule TTP_XOR_WriteProcessMemory_427f {
  strings:
    $key_427f = { 15 0d [2] 27 2f [2] 21 1a [2] 0f 1a [2] 30 06 }

  condition:
    any of them
}