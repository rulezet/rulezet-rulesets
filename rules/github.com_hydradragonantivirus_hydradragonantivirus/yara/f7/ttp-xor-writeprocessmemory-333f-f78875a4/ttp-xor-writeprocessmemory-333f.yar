rule TTP_XOR_WriteProcessMemory_333f {
  strings:
    $key_333f = { 64 4d [2] 56 6f [2] 50 5a [2] 7e 5a [2] 41 46 }

  condition:
    any of them
}