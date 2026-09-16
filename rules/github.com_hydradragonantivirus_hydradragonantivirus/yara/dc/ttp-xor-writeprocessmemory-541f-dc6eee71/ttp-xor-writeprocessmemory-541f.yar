rule TTP_XOR_WriteProcessMemory_541f {
  strings:
    $key_541f = { 03 6d [2] 31 4f [2] 37 7a [2] 19 7a [2] 26 66 }

  condition:
    any of them
}