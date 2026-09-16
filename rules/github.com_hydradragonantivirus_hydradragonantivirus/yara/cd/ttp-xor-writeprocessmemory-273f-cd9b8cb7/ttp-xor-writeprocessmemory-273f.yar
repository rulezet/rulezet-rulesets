rule TTP_XOR_WriteProcessMemory_273f {
  strings:
    $key_273f = { 70 4d [2] 42 6f [2] 44 5a [2] 6a 5a [2] 55 46 }

  condition:
    any of them
}