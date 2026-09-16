rule TTP_XOR_WriteProcessMemory_220f {
  strings:
    $key_220f = { 75 7d [2] 47 5f [2] 41 6a [2] 6f 6a [2] 50 76 }

  condition:
    any of them
}