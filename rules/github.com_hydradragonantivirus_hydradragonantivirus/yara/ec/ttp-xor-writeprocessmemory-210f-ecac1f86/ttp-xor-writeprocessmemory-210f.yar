rule TTP_XOR_WriteProcessMemory_210f {
  strings:
    $key_210f = { 76 7d [2] 44 5f [2] 42 6a [2] 6c 6a [2] 53 76 }

  condition:
    any of them
}