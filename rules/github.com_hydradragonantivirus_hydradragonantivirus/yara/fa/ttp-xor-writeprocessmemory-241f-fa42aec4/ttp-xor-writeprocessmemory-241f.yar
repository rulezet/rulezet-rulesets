rule TTP_XOR_WriteProcessMemory_241f {
  strings:
    $key_241f = { 73 6d [2] 41 4f [2] 47 7a [2] 69 7a [2] 56 66 }

  condition:
    any of them
}