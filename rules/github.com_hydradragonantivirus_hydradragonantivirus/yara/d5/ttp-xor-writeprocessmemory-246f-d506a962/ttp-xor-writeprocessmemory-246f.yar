rule TTP_XOR_WriteProcessMemory_246f {
  strings:
    $key_246f = { 73 1d [2] 41 3f [2] 47 0a [2] 69 0a [2] 56 16 }

  condition:
    any of them
}