rule TTP_XOR_WriteProcessMemory_106f {
  strings:
    $key_106f = { 47 1d [2] 75 3f [2] 73 0a [2] 5d 0a [2] 62 16 }

  condition:
    any of them
}